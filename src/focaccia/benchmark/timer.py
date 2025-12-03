from time import perf_counter

class Timer:
    def __init__(self, name: str = "Timer", paused: bool = False, iterations: int = 1, file_path: str = "benchmark.txt", enabled: bool = True):
        self.name = name
        self.iterations = int(iterations)
        self.total_time = 0
        self.paused = paused
        self.enabled = enabled
        self.file = open(file_path, "a")
        if self.enabled:
            print(f'{self.name}: start timer, do {self.iterations} iterations')
            self.start_time = perf_counter()
        else:
            self.iterations = 1

    def pause(self):
        if self.enabled and not self.paused:
            self.paused = True
            self.total_time += (perf_counter() - self.start_time)

    def unpause(self):
        if self.enabled and self.paused:
            self.paused = False
            self.start_time = perf_counter()

    def log_time(self):
        if self.enabled:
            if not self.paused:
                self.total_time += (perf_counter() - self.start_time)
            time = self.total_time / self.iterations
            print(f'{self.name}: took {time:.5f} seconds')
            self.file.write(f"{self.name}: {time:.5f} seconds\n")
            self.file.close()

    def write_binary(self, binary: str):
        self.file.write(f"\n{binary}:\n")
