#pragma once
#include "blake3.h"
#include <cstring>
#include <span>
#include <string_view>

namespace ml_dsa_hashing {

// BLAKE3 hashing wrapper, behaving like an eXtendable Output Function (XOF).
//
// C++ class wrapper on top of API definition @ https://github.com/BLAKE3-team/BLAKE3/blob/e0b1d91410fd0a344beda6ee0e6f1972ad04be08/c/README.md#api
struct blake3_hasher_t
{
private:
  blake3_hasher internal_hasher;
  bool finalized;
  size_t squeeze_from;

public:
  // Initialize BLAKE3 hasher context.
  blake3_hasher_t()
  {
    blake3_hasher_init(&this->internal_hasher);
    this->finalized = false;
    this->squeeze_from = 0;
  };

  // Initialize BLAKE3 hasher context with a domain separation string.
  explicit blake3_hasher_t(const std::string_view separator)
  {
    blake3_hasher_init_derive_key(&this->internal_hasher, separator.data());
    this->finalized = false;
    this->squeeze_from = 0;
  }

  // Absorb arbitrary length message into BLAKE3 hasher context. Invoke it as many times needed before hasher is finalized.
  void absorb(std::span<const uint8_t> msg)
  {
    if (!this->finalized) {
      blake3_hasher_update(&this->internal_hasher, msg.data(), msg.size());
    }
  }

  // After absorbing full message, finalize hasher, so that it can be used for squeezing output.
  // Once finalized, hasher instance can't be used for further absorption.
  void finalize()
  {
    if (!this->finalized) {
      blake3_hasher_finalize(&this->internal_hasher, nullptr, 0);
      this->finalized = true;
    }
  }

  // After finalizing hasher, start squeezing arbitrary sized output, as many times needed.
  void squeeze(std::span<uint8_t> dig)
  {
    if (this->finalized) {
      blake3_hasher_finalize_seek(&this->internal_hasher, this->squeeze_from, dig.data(), dig.size());
      this->squeeze_from += dig.size();
    }
  }

  // Resets hasher to post-init state. After reseting, the hasher is ready for another round of absorb -> finalize -> squeeze cycle.
  void reset()
  {
    blake3_hasher_reset(&this->internal_hasher);
    this->finalized = false;
    this->squeeze_from = 0;
  }
};

namespace ml_dsa_domains {

inline blake3_hasher_t
G()
{
  return blake3_hasher_t("ML-DSA-B-G");
}

inline blake3_hasher_t
H()
{
  return blake3_hasher_t("ML-DSA-B-H");
}

}

}
