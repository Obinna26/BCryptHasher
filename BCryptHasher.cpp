/// @file   BCryptHasher.cpp
/// @date   2019.07.23
/// @author ttsuki

/// MIT License
/// 
/// Copyright(c) 2019 ttsuki
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files(the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions :
/// 
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include "BCryptHasher.h"

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "Bcrypt.lib")
namespace BCryptHasher
{
	namespace
	{
		class BCryptAlgHandle
		{
			BCRYPT_ALG_HANDLE hAlgorithm_{};

		public:
			BCryptAlgHandle(LPCWSTR hashAlgo, ULONG flags)
			{
				BCRYPT_ALG_HANDLE hAlgorithm{};
				if (BCryptOpenAlgorithmProvider(&hAlgorithm, hashAlgo, NULL, flags) < 0)
				{
					throw std::runtime_error("Failed to BCryptOpenAlgorithmProvider");
				}
				hAlgorithm_ = hAlgorithm;
			}

			BCryptAlgHandle(const BCryptAlgHandle& other) = delete;

			BCryptAlgHandle& operator=(const BCryptAlgHandle& other) = delete;

			~BCryptAlgHandle()
			{
				if (hAlgorithm_)
				{
					BCryptCloseAlgorithmProvider(hAlgorithm_, 0);
				}
			}

			DWORD GetObjectSize() const
			{
				DWORD cbData{};
				DWORD cbObjectSize{};
				BCryptGetProperty(hAlgorithm_, BCRYPT_OBJECT_LENGTH,
					reinterpret_cast<PBYTE>(&cbObjectSize), sizeof(cbObjectSize), &cbData, 0);
				return cbObjectSize;
			}

			DWORD GetHashSize() const
			{
				DWORD cbData{};
				DWORD cbHashSize{};
				BCryptGetProperty(hAlgorithm_, BCRYPT_HASH_LENGTH,
					reinterpret_cast<PBYTE>(&cbHashSize), sizeof(cbHashSize), &cbData, 0);
				return cbHashSize;
			}

			BCRYPT_ALG_HANDLE Handle() const
			{
				return hAlgorithm_;
			}

			operator BCRYPT_ALG_HANDLE() const { return Handle(); }
		};

		class BCryptHashHandle
		{
			DWORD objectSize_{};
			DWORD hashLength_{};
			std::unique_ptr<unsigned char[]> hashObject_{};
			BCRYPT_HASH_HANDLE hHash_{};

		public:
			BCryptHashHandle(const BCryptAlgHandle& algorithm, const void* secretKey = nullptr, size_t secretKeySize = 0)
			{
				objectSize_ = algorithm.GetObjectSize();
				hashLength_ = algorithm.GetHashSize();
				auto obj = std::unique_ptr<unsigned char[]>(new unsigned char[objectSize_]);
				BCRYPT_HASH_HANDLE hHash{};

				auto key = static_cast<PUCHAR>(const_cast<void*>(secretKey));
				auto keyLen = static_cast<DWORD>(secretKeySize);

				if (BCryptCreateHash(algorithm, &hHash, obj.get(), objectSize_, key, keyLen, 0) < 0)
				{
					throw std::runtime_error("Failed to BCryptCreateHash");
				}

				hashObject_ = std::move(obj);
				hHash_ = hHash;
			}

			BCryptHashHandle(const BCryptHashHandle& other) { *this = other; }

			BCryptHashHandle(BCryptHashHandle&& other) noexcept { *this = std::move(other); }

			BCryptHashHandle& operator=(const BCryptHashHandle& other)
			{
				if (this == std::addressof(other)) { return *this; }
				objectSize_ = other.objectSize_;
				hashLength_ = other.hashLength_;
				auto obj = std::unique_ptr<unsigned char[]>(new unsigned char[objectSize_]);
				BCRYPT_HASH_HANDLE hHash{};
				if (BCryptDuplicateHash(other.hHash_, &hHash, obj.get(), objectSize_, 0) < 0)
				{
					throw std::runtime_error("Failed to BCryptDuplicateHash");
				}

				hashObject_ = std::move(obj);
				hHash_ = hHash;
				return *this;
			}

			BCryptHashHandle& operator=(BCryptHashHandle&& other) noexcept
			{
				if (this == std::addressof(other)) { return *this; }
				objectSize_ = other.objectSize_;
				hashLength_ = other.hashLength_;
				hashObject_ = std::move(other.hashObject_);
				hHash_ = other.hHash_;
				other.hHash_ = {};
				return *this;
			}

			~BCryptHashHandle()
			{
				if (hHash_)
				{
					BCryptDestroyHash(hHash_);
					hHash_ = {};
				}
			}

			BCRYPT_HASH_HANDLE Handle() const
			{
				return hHash_;
			}

			operator BCRYPT_HASH_HANDLE() const
			{
				return Handle();
			}

			void Update(const void* pData, size_t cbData)
			{
				if (!hHash_) { throw std::logic_error("not constructed."); }
				if (BCryptHashData(hHash_, static_cast<PUCHAR>(const_cast<void*>(pData)), static_cast<ULONG>(cbData), 0) < 0)
				{
					throw std::runtime_error("Failed to BCryptHashData");
				}
			}

			std::vector<uint8_t> Finish()
			{
				if (!hHash_) { throw std::logic_error("not constructed."); }
				std::vector<uint8_t> hashValue(hashLength_);
				if (BCryptFinishHash(hHash_, hashValue.data(), hashLength_, 0) < 0)
				{
					throw std::runtime_error("Failed to BCryptFinishHash");
				}
				return hashValue;
			}
		};
	}

	namespace
	{
		class BCryptHasher final : public IHasher
		{
			BCryptHashHandle hasher_;

			static BCryptHashHandle CreateBCryptHashHandle(HashAlgorithm algorithm, const void* hmacKey = nullptr, size_t hmacKeyLen = 0)
			{
				auto HashName = [](HashAlgorithm algorithm)-> LPCWSTR
				{
					switch (algorithm)
					{
					case HashAlgorithm::Md5: return BCRYPT_MD5_ALGORITHM;
					case HashAlgorithm::Sha1: return BCRYPT_SHA1_ALGORITHM;
					case HashAlgorithm::Sha256: return BCRYPT_SHA256_ALGORITHM;
					case HashAlgorithm::Sha512: return BCRYPT_SHA512_ALGORITHM;
					default: return nullptr;
					}
				};

				auto name = HashName(algorithm);
				auto flags = static_cast<ULONG>(hmacKey ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);

				BCryptAlgHandle algo{ name, flags };
				if (!algo) { throw std::runtime_error("Failed to BCryptOpenAlgorithmProvider"); }

				BCryptHashHandle handle{ algo, hmacKey, hmacKeyLen };
				if (!handle) { throw std::runtime_error("Failed to BCryptCreateHash"); }

				return handle;
			}

		public:
			BCryptHasher(HashAlgorithm hashAlgo, const void* hmacKey = nullptr, size_t hmacKeyLen = 0)
				: hasher_(CreateBCryptHashHandle(hashAlgo, hmacKey, hmacKeyLen))
			{
			}

			void Update(const void* data, size_t dataLength) override { hasher_.Update(data, dataLength); }
			std::vector<uint8_t> Finish() override { return hasher_.Finish(); }
			std::vector<uint8_t> Value() const override { return BCryptHasher(*this).Finish(); }
		};
	}

	std::unique_ptr<IHasher> CreateBCryptHmacSigner(HashAlgorithm algorithm, const void* hmacKey, size_t hmacKeyLength)
	{
		return std::make_unique<BCryptHasher>(algorithm, hmacKey, hmacKeyLength);
	}

	std::unique_ptr<IHasher> CreateBCryptHasher(HashAlgorithm algorithm)
	{
		return std::make_unique<BCryptHasher>(algorithm);
	}
}
