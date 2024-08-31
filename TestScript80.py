def parseTokenToReturn(token: str) -> str:
    masterIntArray: tuple[
        list[int],
        list[int],
        list[int],
        list[int]
    ] = (
        [0] * 0x10,
        [0] * 0x10,
        [0] * 0x10,
        [0] * 0x10
    )

    for i in range(3, 0x100, 4):
        subIntArray16: list[int] = masterIntArray[i // 0x40]
        index: int = (i // 4) % 0x10

        if i < len(token):
            char: int = ord(token[i])
            subIntArray16[index]: int = (char - (0x57 if char >= 0x3A else 0x30)) & 0xFF
        else:
            subIntArray16[index]: int = 0xF

    I = i = 0
    byteArray64: bytearray = bytearray(b'\x00') * 0x40
    for ri in range(0x1F, -1, -1):
        subIntArray16: list[int] = masterIntArray[ri // 8]
        index: int = (ri * 2) % 0x10
        intBits: int = subIntArray16[index] + subIntArray16[index + 1]

        i: int = I
        while intBits > 0b111:
            byteArray64[i]: int = intBits & 0b111
            intBits >>= 3
            i += 1
        byteArray64[i]: int = intBits
        I: int = i + 1

    tokenReturnChars: bytearray = bytearray(b'\x00') * I
    for j in range(I):
        tokenReturnChars[j]: int = (byteArray64[i] + 0x30) & 0xFF
        i -= 1

    return tokenReturnChars.decode(encoding="utf8")


if __name__ == r"__main__":
    print("Tested Successfully." if parseTokenToReturn(
        "616f1c0c10563f8e28ae3f9f0743fc358a3fa48454e1bca49dcb855b8e0c0aa597ef7b1ddd7f25eca4412a262041ddf3d89a099937d1be9f4ff22dcc3f67d5aa6cce45fbe8ca950185c9f29e2b8cf2da6d79115d6cadab7a5da21a2e584c71f4fccff63d5d4797b9381abcd3de3ed061123e95c1581458d7ee9a44cbdcbf974d"
    ) == "3324351023526213433742320162131132726262720203420151717132534" else "Test Failed!")
