def validate_date(date):
    from .const import DATE_REGEX
    from re import match
    if not match(DATE_REGEX, date):
        raise ValueError(f"Not a valid date ({date}), use format yyyy-mm-dd.")
    return True


def validate_date_range(start, end):
    validate_date(start)
    validate_date(end)
    from datetime import date
    start_date = date.fromisoformat(start)
    end_date = date.fromisoformat(end)
    if start_date > end_date:
        raise ValueError("Start date cannot exceed end date")
    span = end_date - start_date
    if span.days > 365:
        raise ValueError("Date range can only span up to 365 days.")


def validate_seed(seed):
    from .const import DEFAULT_SEED, SEED_REGEX
    from re import match
    if seed != DEFAULT_SEED and not match(SEED_REGEX, seed):
        raise ValueError("Not a valid seed. Must be between 4 and 8 characters")
    return True


def pad_seed(seed):
    return seed + "".join([seed[i] for i in range(0,(10 - len(seed)))])
