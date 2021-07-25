from math import floor, ceil
from .const import TABLE1, TABLE2


def list1(given_date):
    # Last 2 digits in year
    year = int(str(given_date)[2:4])
    month = int(str(given_date.month))
    day_of_month = int(str(given_date.day))
    day_of_week = int(str(given_date.weekday()))
    l1result = []

    for i in range(0, 5):
        l1result.append(TABLE1[day_of_week][i])

    l1result.append(day_of_month)

    if ((year + month) - day_of_month) < 0:
        l1result.append((((year + month) - day_of_month) + 36) % 36)
    else:
        l1result.append(((year + month) - day_of_month) % 36)

    l1result.append((((3 + ((year + month) % 12)) * day_of_month) % 37) % 36)
    return l1result


def list2(seed):
    l2result = []

    for i in range(0, 8):
        seed_char_code = ord(seed[i])
        mod = seed_char_code % 36
        l2result.append(mod)

    return l2result


def num8(l3):
    num8 = l3[8] % 6
    return num8


def last_l3_val(num):
    val = floor(num)
    if (num - val) < 0.50:
        return val
    else:
        return ceil(num)


def list3(l1, l2):
    l3result = []

    for i in range(0, 8):
        l3result.append((((l1[i] + l2[i])) % 36))

    l3_current_sum = sum(l3result)
    l3result.append(l3_current_sum % 36)
    l3_next_val = last_l3_val(num8(l3result)**2)
    l3result.append(l3_next_val)

    return l3result


def list4(l3):
    l4result = []

    for i in range(0, 10):
        val = l3[TABLE2[num8(l3)][i]]
        l4result.append(val)

    return l4result


def list5(seed, l4):
    l5result = []

    for i in range(0, 10):
        char_code_at_i = ord(seed[i])
        val = (char_code_at_i + l4[i]) % 36
        l5result.append(val)

    return l5result


def indexers(date, seed):
    l1 = list1(date)
    l2 = list2(seed)
    l3 = list3(l1, l2)
    l4 = list4(l3)

    return list5(seed, l4)
