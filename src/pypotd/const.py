from string import ascii_uppercase, digits

ALPHANUM = [*digits] + [*ascii_uppercase]
DATE_REGEX = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
SEED_REGEX = "^.{4,8}$"
DEFAULT_SEED = 'MPSJKMDHAI'
DEFAULT_DES = "DB.B5.CB.D6.11.17.D6.EB"
DES_KEY = bytearray([20, 157, 64, 213, 193, 46, 85, 2])
DES_IV = bytearray([0, 0, 0, 0, 0, 0, 0, 0])

TABLE1 = [
    [15, 15, 24, 20, 24],
    [13, 14, 27, 32, 10],
    [29, 14, 32, 29, 24],
    [23, 32, 24, 29, 29],
    [14, 29, 10, 21, 29],
    [34, 27, 16, 23, 30],
    [14, 22, 24, 17, 13]
]

TABLE2 = [
    [0, 1, 2, 9, 3, 4, 5, 6, 7, 8],
    [1, 4, 3, 9, 0, 7, 8, 2, 5, 6],
    [7, 2, 8, 9, 4, 1, 6, 0, 3, 5],
    [6, 3, 5, 9, 1, 8, 2, 7, 4, 0],
    [4, 7, 0, 9, 5, 2, 3, 1, 8, 6],
    [5, 6, 1, 9, 8, 0, 4, 3, 2, 7]
]