def validate_date(date):
    from .const import DATE_REGEX
    from re import match
    if not match(DATE_REGEX, date):
        raise ValueError("Not a valid date, use format yyyy-mm-dd.")
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


def generate(date=None, seed=None):
    from .const import ALPHANUM, DEFAULT_SEED, TABLE1, TABLE2
    from datetime import date as d, datetime
    from math import floor, ceil
    if date == None:
        date = datetime.now().isoformat()[:10]
    if seed == None:
        seed = DEFAULT_SEED
    validate_date(date)
    validate_seed(seed)
    if len(seed) < 10:
        from itertools import cycle, islice
        pad = lambda seed : seed + "".join([char for char in islice(cycle(seed), (10 - len(seed)))])
        seed = pad(seed)
    date = d.fromisoformat(str(date))
    year = int(str(date.year)[2:4])
    month = date.month
    day = date.day
    weekday = date.weekday()
    l1 = [TABLE1[weekday][i] for i in range(0, 5)]
    l1.append(day)
    if ((year + month) - day) < 0:
        l1.append((((year + month) - day) + 36) % 36)
    else:
        l1.append(((year + month) - day) % 36)
    l1.append((((3 + ((year + month) % 12)) * day) % 37) % 36)
    l2 = [(ord(seed[i]) % 36) for i in range(0, 8)]
    l3 = [((l1[i] + l2[i]) % 36) for i in range(0, 8)]
    l3.append(sum(l3) % 36)
    x = (l3[8] % 6)**2
    y = floor(x)
    if x - y < 0.50:
        l3.append(y)
    else:
        l3.append(ceil(x))
    l4 = [l3[TABLE2[(l3[8] % 6)][i]] for i in range(0, 10)]
    result = [((ord(seed[i]) + l4[i]) % 36) for i in range(0, 10)]
    return "".join([ALPHANUM[result[i]] for i in range(0, 10)])


def generate_multiple(start_date, end_date, seed=None):
    if seed == None:
        from .const import DEFAULT_SEED
        seed = DEFAULT_SEED
    validate_date_range(start_date, end_date)
    from datetime import date, timedelta
    def iso(day): return date.fromisoformat(day)
    def fmt(date): return date.strftime("%m/%d/%y")
    def day(delta): return str((iso(start_date) + timedelta(delta)))[:10]
    span = iso(end_date) - iso(start_date)
    days = span.days
    return {
        fmt(iso(day(i))): generate(day(i), seed) for i in range(0, days + 1)
    }


def seed_to_des(seed=None):
    from .const import DEFAULT_DES, DEFAULT_SEED, DES_KEY
    from des import DesKey
    if seed == DEFAULT_SEED or seed == None:
        return DEFAULT_DES
    validate_seed(seed)
    array = bytearray([])
    for i in range(0, len(seed)):
        array.append(ord(seed[i]))
    if len(seed) < 8:
        while len(array) < 8:
            array.append(int(0))
    key = DesKey(DES_KEY)
    _des_out = key.encrypt(bytes(array), initial=0).hex().upper()
    des_out = '.'.join(_des_out[i:i+2] for i in range(0, len(_des_out), 2))
    return des_out
