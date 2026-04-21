const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function retry(fn, attempts = 3, delay = 500) {
  let lastError;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;

      // exponential backoff: 500ms → 1000ms → 2000ms
      await sleep(delay * Math.pow(2, i));
    }
  }

  throw lastError;
}

module.exports = retry;