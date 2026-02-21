// Standalone shim: base/pickle.h
// Minimal Pickle serialization used by libc_interceptor.

#ifndef BASE_PICKLE_H_
#define BASE_PICKLE_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace base {

// Minimal Pickle: length-prefixed binary serialization.
class Pickle {
 public:
  Pickle() { Resize(kHeaderSize); WriteUInt32(0); }

  Pickle(const void* data, size_t data_len)
      : data_(static_cast<const char*>(data),
              static_cast<const char*>(data) + data_len) {}

  const void* data() const { return data_.data(); }
  size_t size() const { return data_.size(); }

  // Writer methods
  void WriteInt(int value) { WriteBytes(&value, sizeof(value)); }
  void WriteUInt32(uint32_t value) { WriteBytes(&value, sizeof(value)); }
  void WriteInt64(int64_t value) { WriteBytes(&value, sizeof(value)); }
  void WriteUInt64(uint64_t value) { WriteBytes(&value, sizeof(value)); }
  void WriteBool(bool value) { WriteInt(value ? 1 : 0); }
  void WriteString(std::string_view value) {
    WriteInt(static_cast<int>(value.size()));
    WriteBytes(value.data(), value.size());
  }
  void WriteBytes(const void* data, size_t len) {
    const char* bytes = static_cast<const char*>(data);
    data_.insert(data_.end(), bytes, bytes + len);
    // Align to 4 bytes
    while (data_.size() % 4 != 0) data_.push_back(0);
  }

  // PickleIterator for reading
  class Iterator {
   public:
    explicit Iterator(const Pickle& pickle)
        : data_(static_cast<const char*>(pickle.data())),
          end_(data_ + pickle.size()),
          pos_(data_ + kHeaderSize) {}

    bool ReadInt(int* result) { return ReadPOD(result); }
    bool ReadUInt32(uint32_t* result) { return ReadPOD(result); }
    bool ReadInt64(int64_t* result) { return ReadPOD(result); }
    bool ReadBool(bool* result) {
      int val;
      if (!ReadInt(&val)) return false;
      *result = val != 0;
      return true;
    }
    bool ReadString(std::string* result) {
      int len;
      if (!ReadInt(&len)) return false;
      if (len < 0 || pos_ + len > end_) return false;
      result->assign(pos_, len);
      pos_ += len;
      AlignPos();
      return true;
    }

   private:
    template <typename T>
    bool ReadPOD(T* result) {
      if (pos_ + sizeof(T) > end_) return false;
      memcpy(result, pos_, sizeof(T));
      pos_ += sizeof(T);
      AlignPos();
      return true;
    }
    void AlignPos() {
      size_t offset = (pos_ - data_) % 4;
      if (offset) pos_ += 4 - offset;
    }
    const char* data_;
    const char* end_;
    const char* pos_;
  };

  // CreateIterator equivalent
  Iterator CreateIterator() const { return Iterator(*this); }

 private:
  static constexpr size_t kHeaderSize = sizeof(uint32_t);
  void Resize(size_t new_size) { data_.resize(new_size); }
  std::vector<char> data_;
};

using PickleIterator = Pickle::Iterator;

}  // namespace base

#endif  // BASE_PICKLE_H_
