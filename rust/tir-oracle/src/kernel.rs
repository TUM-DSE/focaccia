//! Persistent native kernels for pure, specification-derived residual regions.
use super::*;
use backend::oracle_jit::{compile, OracleKernel};
use inkwell::context::Context;
use serde::Deserialize;
use std::{collections::VecDeque, time::Instant};

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Term { bits: u32, input: Option<usize>, constant: Option<String>, op: Option<String>, args: Option<Vec<Term>> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { key: String, widths: Vec<u32>, term: Term, values: Vec<String> }
struct Template { wire: Term, widths: Vec<u32>, module: Module<TypedMeta>, params: Vec<(VarId, TypedTyp)>, body: TypedExpr }
fn typ(bits: u32) -> Result<TypedTyp> {
    if !(1..=128).contains(&bits) { return Err("native kernel width out of range".into()); }
    Ok(TypedTyp::new_bits(TypedExpr::new_lit(Lit::new_int(bits as i64), TypedTyp::Int)))
}
fn number(s: &str, bits: u32) -> Result<u128> {
    let n = u128::from_str_radix(s.strip_prefix("0x").ok_or("expected hexadecimal input")?,16).map_err(|_|"invalid input")?;
    if bits < 128 && n >> bits != 0 { return Err("input exceeds declared width".into()); }
    Ok(n)
}
fn lower(t: &Term, m: &mut Module<TypedMeta>, params: &[(VarId,TypedTyp)], widths: &[u32], budget: &mut usize, depth: usize) -> Result<TypedExpr> {
    if *budget == 0 || depth > 64 { return Err("kernel tree budget exceeded".into()); } *budget -= 1;
    let ty = typ(t.bits)?;
    match (&t.input,&t.constant,&t.op,&t.args) {
        (Some(i),None,None,None) => {
            if widths.get(*i) != Some(&t.bits) { return Err("kernel input type mismatch".into()); }
            Ok(TypedExpr::new_id(params[*i].0,ty))
        },
        (None,Some(v),None,None) => {
            let n=number(v,t.bits)?;
            Ok(TypedExpr::new_lit(Lit::Bits(format!("{n:0width$b}",width=t.bits as usize).into()),ty))
        },
        (None,None,Some(op),Some(args)) => {
            if args.len()!=2 || (if op == "concat" {
                args[0].bits.checked_add(args[1].bits) != Some(t.bits)
            } else { args.iter().any(|a| a.bits!=t.bits) }) { return Err("invalid binary kernel signature".into()); }
            let primitive=match op.as_str() { "concat"=>Primitive::AppendBits, "+"=>Primitive::AddBits,"-"=>Primitive::SubBits,"*"=>Primitive::MulBits,"&"=>Primitive::AndBits,"|"=>Primitive::OrBits,"^"=>Primitive::EorBits,_=>return Err("unsupported kernel operation".into()) };
            let args=args.iter().map(|a|lower(a,m,params,widths,budget,depth+1)).collect::<Result<Vec<_>>>()?;
            let fid=m.fresh("kernel_primitive"); let x=m.fresh("x"); let y=m.fresh("y");
            m.entries.push(Decl::Primitive { id:fid, ret_typ:ty.clone(),params:vec![(x,args[0].meta.typ.clone()),(y,args[1].meta.typ.clone())],name:primitive });
            Ok(TypedExpr::new_app(TypedExpr::new_id(fid,TypedTyp::Arrow(vec![args[0].meta.typ.clone(),args[1].meta.typ.clone()],std::sync::Arc::new(ty.clone()))),&args,ty))
        },
        _=>Err("invalid kernel term".into()),
    }
}

pub fn run() -> Result<()> {
    let configured=super::configured_spec()?;
    let context=Context::create();
    let mut templates: HashMap<String,Template>=HashMap::new();
    let mut order=VecDeque::new();
    let mut kernels: HashMap<(String,Vec<(usize,u128)>),OracleKernel<'_>>=HashMap::new();
    let mut kernel_order=VecDeque::new();
    let mut compilations=0usize;
    for line in std::io::stdin().lock().lines() {
        let line=line.map_err(|e|e.to_string())?;
        if line.len()>1_000_000 { return Err("kernel request too large".into()); }
        let request:Request=serde_json::from_str(&line).map_err(|e|e.to_string())?;
        if request.key.len()>256 || request.widths.len()>256 || request.values.len()!=request.widths.len() { return Err("invalid kernel request dimensions".into()); }
        for w in &request.widths { typ(*w)?; }
        let values=request.values.iter().zip(&request.widths).map(|(v,w)|number(v,*w)).collect::<Result<Vec<_>>>()?;
        let template_hit=templates.contains_key(&request.key);
        let start=Instant::now();
        if !template_hit {
            if templates.len()>=128 { let old=order.pop_front().unwrap(); templates.remove(&old); }
            let mut module=Module::default(); module.arch=configured.arch.clone();
            let mut params=Vec::new();
            for w in &request.widths { let id=module.fresh("input"); params.push((id,typ(*w)?)); }
            let body=lower(&request.term,&mut module,&params,&request.widths,&mut 4096,0)?;
            // Stage one reduces literals while preserving execution-dependent parameters.
            let (module,body)=specializer::oracle::reduce(&module,&params,&body,&HashMap::new())?;
            templates.insert(request.key.clone(),Template {wire:request.term.clone(),widths:request.widths.clone(),module,params,body});
            order.push_back(request.key.clone());
        }
        let template=templates.get(&request.key).unwrap();
        if template.wire!=request.term || template.widths!=request.widths { return Err("template identity mismatch".into()); }
        // Bound the variant space by specializing at most three one-bit inputs.
        // Values are guards on entry operands, never observed outputs.
        let guards:Vec<_>=request.widths.iter().enumerate().filter(|(_,w)|**w==1).take(3).map(|(i,_)|(i,values[i])).collect();
        let key=(request.key.clone(),guards.clone());
        let variant_hit=kernels.contains_key(&key);
        let reduction_seconds;
        let mut compile_seconds=0.0;
        if !variant_hit {
            if compilations>=10000 { return Err("native compilation budget exceeded".into()); }
            let bindings=guards.iter().map(|(i,v)|(template.params[*i].0,Lit::Bits(format!("{v:b}").into()))).collect();
            // Stage two runs TIR's evaluator on the RETAINED stage-one residual.
            let (module,body)=specializer::oracle::reduce(&template.module,&template.params,&template.body,&bindings)?;
            reduction_seconds=start.elapsed().as_secs_f64();
            let compile_start=Instant::now();
            let kernel=compile(&context,&module,&template.params,&body)?;
            compile_seconds=compile_start.elapsed().as_secs_f64();
            if kernels.len()>=256 { let old=kernel_order.pop_front().unwrap(); kernels.remove(&old); }
            kernels.insert(key.clone(),kernel); kernel_order.push_back(key.clone()); compilations+=1;
        } else { reduction_seconds=start.elapsed().as_secs_f64(); }
        let value=kernels.get(&key).unwrap().evaluate(&values)?;
        println!("{}",serde_json::json!({"value":format!("0x{value:x}"),"template_hit":template_hit,"variant_hit":variant_hit,"guards":guards.len(),"reduction_seconds":reduction_seconds,"compile_seconds":compile_seconds}));
        std::io::stdout().flush().map_err(|e|e.to_string())?;
    }
    Ok(())
}
