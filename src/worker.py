"""Small retrying queue worker used by the compatibility fixture."""


def process(job, attempts=3):
    for attempt in range(attempts):
        try:
            return job()
        except RuntimeError:
            if attempt + 1 == attempts:
                raise

