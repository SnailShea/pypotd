# pypotd

Python library to generate an ARRIS/Commscope-compatible password of the day.
Inspired by [arrispwgen](https://github.com/borfast/arrispwgen).

The original author essentially reverse-engineered the algorithm after poking modems. Thank you so much @borfast for this incredible work. I ran into a few niche issues based on my needs/specific seed that I hope this project will rectify.

First, the upstream project seems to lock you to a seed between 8-10 characters. The original ARRIS/Commscope tooling to generate these passwords actually only allows seeds between 4-8 characters. (I find this strange, considering that the default ARRIS/Commscope seed is 10 characters in length)

Second, if you supply a seed of less than 10 characters, the upstream project will present a password of the same number of characters. So an 8 character seed will yield the _correct_ first 8 characters of the password, but will not provide the _full_ password.

Third, if you supply a seed of less than 8 characters, the upstream project does not appear to output anything at all. The way ARRIS/Commscope handles the seeds is to iterate through the seed, appending each character to the end of the supplied seed. For example, a seed of "ABCD" is a _valid seed_, however in effect it will become "ABCDABCDAB".

Fourth, as much as I would love to contribute upstream fixes rather than a fork/port, the upstream project was written in TypeScript and packaged via NPM. I do not have experience with either of these technologies, and as such a port became much more viable.

# Installing

`pip install pypotd`

# Usage

## Single date

The `generate()` function accepts two optional keyword arguments.

- `date`: Accepts a single date in ISO format (i.e., 2021-07-23)
- `seed`: Accepts a seed between 4 and 8 characters

If no arguments are given, the current date and default seed are used.

### Using defaults (current date, ARRIS/Commscope default seed)

```python
from pypotd import generate

generate()
```

Output (Assuming date is 2023-09-23): `4503603RL6`

### Using custom date, custom seed

```python
from pypotd import generate

generate(date="2023-09-23", seed="ABCDABCD")
```

Output: `AYGLYLIF4L`

## Range of dates

The `generate_multiple()` function takes a start and end date, as well as an optional seed.

### Using default seed

```python
from json import dumps
from pypotd import generate_multiple

potd_dict = generate_multiple(start_date="2023-09-23", end_date="2024-09-22")
print(dumps(potd_dict), indent=2)
```

Output (truncated):

```
{
  "09/23/23": "4503603RL6",
  "09/24/23": "ZOU3MA9ZM5",
  "09/25/23": "L776USZKFV",
  ...
}
```

### Using custom seed

```python
from json import dumps
from pypotd import generate_multiple

potd_dict = generate_multiple(
    start_date="2023-09-23",
    end_date="2024-09-22",
    seed="ABCDABCD")
print(dumps(potd_dict, indent=2))
```

Output (truncated):

```
{
  "09/23/23": "AYGLYLIF4L",
  "09/24/23": "BXBL4119CV",
  "09/25/23": "13EW9BEY5O",
  ...
}
```

## Generating a DES Key for modem configs

Despite the fact that ARRIS/CommScope tools limit seed length to between 4 and 8 characters, the default seed they provide is 10 characters. This does not fit neatly into the 8 byte block size of our DES cipher. I was not able to determine what mutations they make to the default seed to return 8 byte values, so the DES value for their default seed is provided as a hardcoded fallback.

```python
from pypotd import seed_to_des

seed_to_des("ABCDABCD")
```

Output:

```
'19.A2.3B.2A.F0.A0.F6.15'
```

# License
This project is a fork and language port of a project made by another individual, whose work was partially aided by reverse engineering. Because of this, I have decided to leave the project unlicensed.