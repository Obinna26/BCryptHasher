# BCryptHasher
Win32 BCrypto API HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-512 Signer Wrapper Library.

## Simple Usage

```cpp
// Sign with HMAC-SHA-256.
auto signer = BCryptHasher::CreateHmacSha256Signer("Jefe", 4); // HMACKey, KeyLength
signer->Update("what do ya want ", 16);
signer->Update("for nothing?", 12);
auto signature = signer->Finish();

// Print the signature.
for (auto c : signature)
{
    std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);0xD445b5d483fA52e2C3FdDE2352821371349aAEac
}
std::cout << std::endl;
```

## Functions

See [BCryptHasher.h](BCryptHasher.h)

## License
[MIT](LICENSE)

