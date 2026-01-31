#pragma once
#define HASH(string) []() { constexpr unsigned long h = HashStringDjb2(string); return h; }()
#define XOR(string) XorString<sizeof(string)>(string).decrypt()

__forceinline constexpr unsigned long CalculateHashSeed() {
    unsigned long seed = 5381;
    for (int i = 0; i < 8; i++)
        seed = ((seed << 5) + seed) + __TIME__[i];
    seed = (seed ^ (seed >> 16)) * 0x85ebca6b;
    seed = (seed ^ (seed >> 13)) * 0xc2b2ae35;
    seed = (seed ^ (seed >> 16));
    return seed;
}

inline constexpr unsigned long HASH_SEED = CalculateHashSeed();
inline constexpr unsigned char XOR_KEY = (unsigned char)(HASH_SEED);

template <typename T>
__forceinline constexpr unsigned long HashStringDjb2(const T* str) {
    unsigned long hash = HASH_SEED;
    while (*str) {
        T c = *str;
        if (c >= (T)'a' && c <= (T)'z')
            c -= 0x20;
        hash = ((hash << 5) + hash) + (unsigned long)c;
        str++;
    }
    return hash;
}

template <size_t N>
struct XorString {
    template<size_t... Is>
    struct Seq {};

    template<size_t M, size_t... Is>
    struct GenSeq : GenSeq<M - 1, M - 1, Is...> {};

    template<size_t... Is>
    struct GenSeq<0, Is...> : Seq<Is...> {};

    char data[N];

    __forceinline constexpr XorString(const char* str) : XorString(str, GenSeq<N>{}) {}

    template <size_t... Is>
    __forceinline constexpr XorString(const char* str, Seq<Is...>)
        : data{ static_cast<char>(str[Is] ^ XOR_KEY)... } {
    }

    __forceinline char* decrypt() {
        for (volatile size_t i = 0; i < N; i++) {
            data[i] ^= XOR_KEY;
        }
        return data;
    }
};