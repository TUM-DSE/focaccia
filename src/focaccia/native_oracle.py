"""Hot pure residual regions reduced in TIR and compiled to evidence-only LLVM kernels."""
import hashlib
import json
import select
import subprocess
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass

from miasm.expression.expression import ExprCompose, ExprInt, ExprOp
from focaccia.symbolic import SymbolEvaluationError


@dataclass
class KernelPlan:
    root: object
    term: dict
    leaves: tuple
    digest: str


class NativeOracle:
    """Bounded native tier over the same specification-derived residual.

    Native kernels receive scalar input slots, never guest pointers. Memory and
    other non-native expressions are evaluated through the resumable evaluator.
    Cold regions retain that evaluator; native-tier failures are fatal.
    """
    OPERATIONS = {"+", "-", "*", "&", "|", "^"}

    def __init__(self, oracle, *, timeout=60.0, hot_after=2):
        if hot_after < 1:
            raise ValueError("hot threshold must be positive")
        self.timeout = timeout
        self.hot_after = hot_after
        self.plans = OrderedDict()
        self.hits = OrderedDict()
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            [oracle, "--jit-kernels"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr,
        )
        self.stats = dict(native_calls=0, template_hits=0, variant_hits=0,
                          compilations=0, guarded_calls=0,
                          reduction_seconds=0.0, compile_seconds=0.0,
                          roundtrip_seconds=0.0)

    def plan(self, expression):
        key = id(expression)
        if key in self.plans:
            self.plans.move_to_end(key)
            return self.plans[key]
        if not (isinstance(expression, ExprCompose) or (
            isinstance(expression, ExprOp) and expression.op in self.OPERATIONS
        )):
            return None
        leaves = []
        indices = {}
        budget = [1024]

        def lower(node, depth=0):
            budget[0] -= 1
            if budget[0] < 0 or depth > 48 or not 1 <= node.size <= 128:
                raise ValueError("native region budget")
            base = {"bits": node.size}
            if isinstance(node, ExprInt):
                return dict(base, constant=hex(int(node)))
            if isinstance(node, ExprCompose):
                args = [lower(a, depth + 1) for a in node.args]
                result = args[0]
                for arg in args[1:]:
                    result = dict(bits=arg["bits"] + result["bits"],
                                  op="concat", args=[arg, result])
                return result
            if (isinstance(node, ExprOp) and node.op in self.OPERATIONS
                    and len(node.args) >= 2
                    and all(a.size == node.size for a in node.args)):
                args = [lower(a, depth + 1) for a in node.args]
                result = args[0]
                for arg in args[1:]:
                    result = dict(base, op=node.op, args=[result, arg])
                return result
            if id(node) not in indices:
                indices[id(node)] = len(leaves)
                leaves.append(node)
            return dict(base, input=indices[id(node)])

        try:
            term = lower(expression)
        except ValueError:
            return None
        if "op" not in term or len(leaves) > 256:
            return None
        digest = hashlib.sha256(json.dumps(term, sort_keys=True).encode()).hexdigest()
        plan = KernelPlan(expression, term, tuple(leaves), digest)
        self.plans[key] = plan  # Holds the root alive while keyed by identity.
        if len(self.plans) > 512:
            self.plans.popitem(last=False)
        return plan

    def hot(self, plan, context):
        key = (str(context), plan.digest)
        count = self.hits.get(key, 0) + 1
        self.hits[key] = count
        self.hits.move_to_end(key)
        if len(self.hits) > 2048:
            self.hits.popitem(last=False)
        return count >= self.hot_after

    def evaluate(self, plan, values, context):
        key = hashlib.sha256((str(context) + ":" + plan.digest).encode()).hexdigest()
        request = dict(key=key, widths=[leaf.size for leaf in plan.leaves],
                       term=plan.term, values=[hex(int(v)) for v in values])
        payload = json.dumps(request).encode() + b"\n"
        if len(payload) > 1_000_000:
            raise SymbolEvaluationError("Native request budget exceeded")
        started = time.monotonic()
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
            if not select.select([self.process.stdout], [], [], self.timeout)[0]:
                raise SymbolEvaluationError("Native oracle response timeout")
            response = self.process.stdout.readline(1_000_001)
            if not response or len(response) > 1_000_000:
                self.stderr.seek(0)
                detail = self.stderr.read(2048).decode(errors="replace")
                raise SymbolEvaluationError(f"Native oracle failed: {detail}")
            result = json.loads(response)
            value = int(result["value"], 16)
            if not 0 <= value < 1 << plan.root.size:
                raise ValueError("native result width")
        except (OSError, ValueError, KeyError) as error:
            raise SymbolEvaluationError("Invalid native oracle response") from error
        self.stats["native_calls"] += 1
        self.stats["template_hits"] += int(result["template_hit"])
        self.stats["variant_hits"] += int(result["variant_hit"])
        self.stats["compilations"] += int(not result["variant_hit"])
        self.stats["guarded_calls"] += int(result["guards"] > 0)
        self.stats["reduction_seconds"] += result["reduction_seconds"]
        self.stats["compile_seconds"] += result["compile_seconds"]
        self.stats["roundtrip_seconds"] += time.monotonic() - started
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close()
