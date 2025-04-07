"""
Performance optimization utilities
"""

import os
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import wraps

def timeit(func):
    """
    Decorator to measure the execution time of a function
    
    Args:
        func: Function to measure
        
    Returns:
        Wrapped function that prints execution time
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Function {func.__name__} took {end_time - start_time:.2f} seconds to run")
        return result
    return wrapper

def run_with_timeout(func, args=None, kwargs=None, timeout=300):
    """
    Run a function with a timeout
    
    Args:
        func: Function to run
        args: Arguments to pass to the function
        kwargs: Keyword arguments to pass to the function
        timeout: Timeout in seconds
        
    Returns:
        Result of the function or None if timeout
    """
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        return None, TimeoutError(f"Function {func.__name__} timed out after {timeout} seconds")
    
    if exception[0] is not None:
        return None, exception[0]
    
    return result[0], None

def parallel_analyze(analyzers, contract_dir, max_workers=None):
    """
    Run analyzers in parallel
    
    Args:
        analyzers: Dictionary of analyzer name to analyzer instance
        contract_dir: Directory containing the contract source code
        max_workers: Maximum number of workers (default: number of CPUs)
        
    Returns:
        Dictionary of analyzer name to analysis results
    """
    if max_workers is None:
        max_workers = min(len(analyzers), multiprocessing.cpu_count())
    
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_analyzer = {
            executor.submit(analyzer.analyze, contract_dir): name
            for name, analyzer in analyzers.items()
        }
        
        for future in as_completed(future_to_analyzer):
            name = future_to_analyzer[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {
                    "success": False,
                    "error": f"Analyzer failed: {str(e)}",
                    "vulnerabilities": []
                }
    
    return results

def cache_results(func):
    """
    Decorator to cache the results of a function
    
    Args:
        func: Function to cache
        
    Returns:
        Wrapped function that caches results
    """
    cache = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Create a cache key from the arguments
        key = str(args) + str(sorted(kwargs.items()))
        
        # Check if the result is already cached
        if key in cache:
            return cache[key]
        
        # Call the function and cache the result
        result = func(*args, **kwargs)
        cache[key] = result
        return result
    
    return wrapper
