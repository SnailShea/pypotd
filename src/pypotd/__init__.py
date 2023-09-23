def seed_to_des(seed=None):
    from .const import DEFAULT_DES, DEFAULT_SEED
    if seed == DEFAULT_SEED or seed == None:
        return DEFAULT_DES
    from .const import DES_IV, DES_KEY
    from Cryptodome.Cipher import DES
    array = bytearray([])
    des = DES.new(DES_KEY, DES.MODE_CBC, iv=DES_IV)
    for i in range(0, len(seed)):
        array.append(ord(seed[i]))
    if len(seed) < 8:
        while len(array) < des.block_size:
            array.append(int(0))
    _des_out = des.encrypt(array).hex().upper()
    des_out = '.'.join(_des_out[i:i+2] for i in range(0, len(_des_out), 2))
    return des_out


def generate(date=None, seed=None):
    from .const import ALPHANUM, DEFAULT_SEED, TABLE1, TABLE2
    from .func import pad_seed, validate_date, validate_seed
    from datetime import date as d, datetime
    from math import floor, ceil
    if date == None:
        date = datetime.now().isoformat()[:10]
    if seed == None:
        seed = DEFAULT_SEED
    validate_date(date)
    validate_seed(seed)
    if len(seed) < 10:
        seed = pad_seed(seed)
    date = d.fromisoformat(str(date))
    year = int(str(date.year)[2:4])
    month = date.month
    day = date.day
    weekday = date.weekday()
    l1 = [TABLE1[weekday][i] for i in range(0,5)]
    l1.append(day)
    if ((year + month) - day) < 0:
        l1.append((((year + month) - day) + 36) % 36)
    else:
        l1.append(((year + month) - day) % 36)
    l1.append((((3 + ((year + month) % 12)) * day) % 37) % 36)
    l2 = [(ord(seed[i]) % 36) for i in range(0,8)]
    l3 = [((l1[i] + l2[i]) % 36) for i in range(0,8)]
    l3.append(sum(l3) % 36)
    x = (l3[8] % 6)**2
    y = floor(x)
    if x - y < 0.50:
        l3.append(y)
    else:
        l3.append(ceil(x))
    l4 = [l3[TABLE2[(l3[8] % 6)][i]] for i in range(0,10)]   
    result = [((ord(seed[i]) + l4[i]) % 36) for i in range(0,10)]
    return "".join([ALPHANUM[result[i]] for i in range(0, 10)])


def generate_multiple(start_date, end_date, seed=None):
    from .func import validate_date_range
    if seed == None:
        from .const import DEFAULT_SEED
        seed = DEFAULT_SEED
    validate_date_range(start_date, end_date)
    from datetime import date, timedelta
    iso = lambda day : date.fromisoformat(day)
    fmt = lambda date: date.strftime("%m/%d/%y")
    day = lambda delta : str((iso(start_date) + timedelta(delta)))[:10]
    span = iso(end_date) - iso(start_date)
    days = span.days
    return {
        fmt(iso(day(i))):generate(day(i), seed) for i in range(0, days + 1)
    }

