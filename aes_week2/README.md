# Demo AES-128 bằng Python

Cài đặt thuật toán AES-128 để học và đối chiếu với FIPS 197. Chương trình
mã hóa một khối 16 byte, giải mã bằng cùng khóa và kiểm tra dữ liệu khôi phục
có trùng đầu vào hay không. Có thể xem từng khóa vòng và trạng thái trung gian
(State) dưới dạng hex và ma trận 4 × 4.

## Chạy demo

Yêu cầu Python 3.10 trở lên, không cần cài thêm thư viện.
Mở terminal tại thư mục `aes_week2`:

```sh
python demo.py
python demo.py --trace
```

Kết quả mặc định dùng ví dụ FIPS 197 (2001), Phụ lục C.1:

```text
Plaintext : 00112233445566778899aabbccddeeff
Key       : 000102030405060708090a0b0c0d0e0f
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
Recovered : 00112233445566778899aabbccddeeff
FIPS C.1  : PASS
Round-trip: PASS
```

`FIPS C.1` đối chiếu ciphertext với giá trị chuẩn khi dùng đúng đầu vào mẫu.
`Round-trip` kiểm tra bản rõ khôi phục trùng từng byte với đầu vào ở mọi lần chạy.
`--trace` hiển thị riêng hai phần `ENCRYPT` và `DECRYPT`; vòng giải mã được
đánh số 0–10, dùng khóa theo thứ tự K10–K0.

Nhập dữ liệu riêng bằng hex hoặc văn bản UTF-8:

```sh
python demo.py --plaintext 00112233445566778899aabbccddeeff --key 000102030405060708090a0b0c0d0e0f
python demo.py --text "AES week 2 demo!"
```

Khối dữ liệu và khóa phải dài đúng 16 byte (32 chữ số hex). `--text` và
`--plaintext` không dùng cùng lúc. Văn bản phải có đúng 16 byte sau khi mã hóa
UTF-8, không nhất thiết là 16 ký tự; demo in thêm văn bản sau khi khôi phục.
Nếu bỏ `--key`, chương trình dùng khóa mẫu ở trên.

## Mã nguồn và kiểm thử

- `aes.py`: mở rộng khóa, các phép biến đổi và hai hàm `encrypt_block`, `decrypt_block`.
- `demo.py`: nhập dữ liệu, chạy mã hóa → giải mã và hiển thị kết quả.
- `test_aes.py`: kiểm tra hai chiều bằng vector NIST, khóa vòng, trạng thái
  trung gian, tính nghịch đảo, khôi phục dữ liệu và đầu vào dòng lệnh.

Chạy kiểm thử trong thư mục `aes_week2`:

```sh
python -m unittest -v
```

Phạm vi hiện tại là AES-128 một khối, chưa có padding, xử lý thông điệp nhiều
khối, xác thực dữ liệu hoặc truyền mạng. Mã phục vụ học tập; trace hiển thị
khóa và dữ liệu trung gian, chỉ dùng với dữ liệu thử nghiệm.

## Tài liệu tham khảo

- [FIPS 197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1): đặc tả thuật toán AES.
- [FIPS 197 (2001), Phụ lục C.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf): ví dụ và trạng thái trung gian.
- [NIST AES_Core128](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf): các khối kiểm thử bổ sung.
