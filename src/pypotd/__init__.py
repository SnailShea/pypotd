from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad
from datetime import date, datetime, timedelta
from re import match
from .const import ALPHANUM, DATE_REGEX, DEFAULT_DATE, DEFAULT_SEED, SEED_REGEX
from .data import indexers


def generate(potd_date=DEFAULT_DATE, seed=DEFAULT_SEED):
    date_valid = is_valid_date(potd_date)
    if date_valid:
        potd_date = date.fromisoformat(str(potd_date))
        if seed != DEFAULT_SEED:
            seed = validate_seed(seed)
        idx = indexers(potd_date, seed)
        potd = []
        for i in range(0, 10):
            potd.append(ALPHANUM[idx[i]])
    return "".join(potd)


def generate_multiple(start_date, end_date, seed=DEFAULT_SEED):
    dates_valid = is_valid_range(start_date, end_date)
    if dates_valid:
        start_date = date.fromisoformat(start_date)
        end_date = date.fromisoformat(end_date)
        potd_dict = {}
        span = end_date - start_date
        for i in range(0, span.days + 1):
            tgt_date = date.fromisoformat(str(start_date + timedelta(i))[:10])
            fmt_date = tgt_date.strftime("%m/%d/%y")
            potd = generate(potd_date=tgt_date, seed=seed)
            potd_dict[fmt_date] = potd
    return potd_dict


def is_valid_date(date):
    # TODO: Add support for date ranges
    # TODO: Ensure date ranges span only 1-365 days
    # TODO: Ensure that start date is older than end date
    if not match(DATE_REGEX, date):
        raise ValueError("Not a valid date, use format 2021-07-23.")
    else:
        return True


def validate_seed(seed):
    if not match(SEED_REGEX, seed):
        raise ValueError(
            "Not a valid seed. Must be between 4 and 8 characters")
    elif len(seed) < 10:
        len_diff = 10 - len(seed)
        for i in range(0, len_diff):
            seed = seed + seed[i]
    return seed


def is_valid_range(start_date, end_date):
    if not match(DATE_REGEX, start_date):
        raise ValueError("Not a valid date, use format 2021-07-23.")
    if not match(DATE_REGEX, end_date):
        raise ValueError("Not a valid date, use format 2021-07-23.")
    start_date = date.fromisoformat(start_date)
    end_date = date.fromisoformat(end_date)
    span = end_date - start_date
    if start_date > end_date:
        raise ValueError("End date cannot be before start date.")
    elif span.days + 1 > 365:
        raise ValueError("Date range can only span up to 365 days.")
    else:
        return True


def seed_to_des(seed):
    # Must be run on unpadded seed, or the seed will exceed the DES block size
    default_des = "DB.B5.CB.D6.11.17.D6.EB"
    if seed == DEFAULT_SEED:
        return default_des
    else:
        key = bytearray([20, 157, 64, 213, 193, 46, 85, 2])
        iv = bytearray([0, 0, 0, 0, 0, 0, 0, 0])
        array = bytearray([])
        for i in range(0, len(seed)):
            array.append(ord(seed[i]))
        des = DES.new(key, DES.MODE_CBC, iv=iv)
        if len(seed) < 8:
            print("Seed too small, padding")
            while len(array) < des.block_size:
                array.append(int(0))
        _des_out = des.encrypt(array).hex().upper()
        des_out = '.'.join(_des_out[i:i+2] for i in range(0, len(_des_out), 2))
        return des_out
