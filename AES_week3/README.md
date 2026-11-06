# AES-128 - Học phần PBL3 (Tuần 3)

Cài đặt chuẩn mã hóa **AES-128** (NIST FIPS 197). Phiên bản Tuần 3 bổ sung chế độ CBC, đệm PKCS#7, dẫn xuất khóa từ mật khẩu và mã hóa/giải mã file.

## Cấu trúc thư mục

| File | Vai trò |
|---|---|
| `aes.py` | Lõi AES (`class AES`), đệm PKCS#7, chế độ CBC, sinh/dẫn xuất khóa, mã hóa/giải mã file |
| `demo.py` | Chương trình demo dòng lệnh |
| `test_aes.py` | Bộ kiểm thử tự động (unittest) |
| `README.md` | Tài liệu này |

## Điểm mới của Tuần 3

Kế thừa kết quả khảo sát lý thuyết ở Tuần 2, phiên bản Tuần 3 có các thay đổi sau:

1. **Kiến trúc ma trận 2D (`class AES`)**
   * State là ma trận 4×4 lưu theo cột, truy cập bằng `s[col][row]`; khởi tạo bằng `aes = AES(key)`.
   * Cấu trúc State ma trận tham khảo từ [`boppreh/aes`](https://github.com/boppreh/aes).
   * Phép nhân cột `mix_columns` và `inv_mix_columns` theo công thức đại số trong sách *The Design of Rijndael*.
2. **Sinh khóa và dẫn xuất khóa**
   * Sinh khóa ngẫu nhiên bằng CSPRNG của hệ điều hành (`os.urandom`).
   * Dẫn xuất khóa 128-bit từ mật khẩu bằng `PBKDF2-HMAC-SHA256` (salt 16 byte ngẫu nhiên, 100.000 vòng lặp).
3. **Đệm dữ liệu PKCS#7**
   * Cho phép mã hóa dữ liệu có độ dài bất kỳ (thêm 1 đến 16 byte đệm; dữ liệu vừa đủ bội số của 16 vẫn được đệm thêm một khối).
   * `unpad` kiểm tra byte đệm và báo `ValueError` khi đệm sai.
4. **Chế độ CBC (Cipher Block Chaining)**
   * Dùng IV ngẫu nhiên 16 byte cho mỗi lần mã hóa.
   * Các khối bản rõ giống nhau cho ra bản mã khác nhau, khác với chế độ ECB.
5. **Mã hóa và giải mã file**
   * File được đọc dưới dạng bytes nên áp dụng được cho mọi định dạng (`.zip`, `.pdf`, `.docx`, `.png`, `.txt`...).
   * Hàm trả về mã băm SHA-256 của file gốc và của file sau giải mã để đối chiếu.

### Cấu trúc file mã hóa (`.enc`)

Có hai dạng, tùy cách mã hóa:

| Cách mã hóa | Cấu trúc file |
|---|---|
| Khóa 16 byte trực tiếp (`--key`) | `[IV 16 byte] + [bản mã CBC]` |
| Mật khẩu (`--password`) | `[magic "AES3PWD\0" 8 byte] + [salt 16 byte] + [IV 16 byte] + [bản mã CBC]` |

Khi giải mã, chương trình nhận biết dạng thứ hai bằng 8 byte magic ở đầu file và tự lấy salt để dựng lại khóa từ mật khẩu.

## Yêu cầu

* Python 3 (đã chạy thử trên Python 3.12), không cần cài thêm gói nào.
* Đặt `aes.py`, `demo.py`, `test_aes.py` trong cùng một thư mục và chạy lệnh tại thư mục đó.

## Hướng dẫn chạy

### 1. Chạy kiểm thử tự động

```bash
python -m unittest -v test_aes.py
```

Kết quả mong đợi: `Ran 13 tests ... OK`. Các test bao gồm:

* Vector chuẩn FIPS 197 Phụ lục C.1 (mã hóa và giải mã) và 4 khối NIST Core.
* Chế độ CBC đối chiếu NIST SP 800-38A Phụ lục F.2.1.
* Đệm PKCS#7 với nhiều độ dài biên và trường hợp đệm bị hỏng.
* Sinh khóa, dẫn xuất khóa PBKDF2, CBC với nhiều độ dài dữ liệu.
* Mã hóa/giải mã file nhị phân, file ZIP và file dùng mật khẩu.
* Ném ngoại lệ khi tham số sai kích thước.

### 2. Chạy demo (`demo.py`)

#### A. Mã hóa một khối 16 byte theo FIPS 197 C.1

```bash
python demo.py
```

Kết quả mong đợi: bản mã `69c4e0d86a7b0430d8cdb78070b4c55a`, kèm hai dòng `PASS` (đối chiếu NIST C.1 và kiểm tra hai chiều).

Thêm cờ `--trace` để xem State dạng ma trận 4×4 qua từng bước biến đổi:

```bash
python demo.py --trace
```

#### B. Mã hóa văn bản bất kỳ bằng mật khẩu (CBC + PKCS#7)

```bash
python demo.py --text "Học phần PBL3 Mạng máy tính" --password "MatKhauBaoMat@2026"
```

Chương trình in salt, khóa dẫn xuất, IV, bản mã và văn bản sau giải mã. Lưu ý: lệnh này in cả mật khẩu và khóa ra màn hình, chỉ nên dùng với mật khẩu mẫu.

#### C. Tự động mã hóa và giải mã một file ZIP

```bash
python demo.py --demo-zip
```

Lệnh này lần lượt:

1. Tạo `sample_archive.zip` chứa 2 tài liệu mẫu (373 byte).
2. Mã hóa thành `sample_archive.zip.enc` bằng AES-128-CBC (400 byte = 16 byte IV + 384 byte bản mã).
3. Giải mã thành `sample_archive_recovered.zip`.
4. So sánh SHA-256 trước và sau giải mã (kết quả mong đợi: `PASS`).
5. Mở file ZIP đã khôi phục và đọc nội dung bên trong.

Ba file sinh ra nằm cùng thư mục với `demo.py`; có thể xóa sau khi chạy xong.

#### D. Mã hóa và giải mã file tùy chọn

Dùng mật khẩu:

```bash
python demo.py --encrypt-file "tailieu.pdf" --out "tailieu.pdf.enc" --password "MySecretPass"
python demo.py --decrypt-file "tailieu.pdf.enc" --out "tailieu_giaima.pdf" --password "MySecretPass"
```

Dùng khóa 16 byte (32 ký tự hex):

```bash
python demo.py --encrypt-file "tailieu.pdf" --out "tailieu.pdf.enc" --key 000102030405060708090a0b0c0d0e0f
python demo.py --decrypt-file "tailieu.pdf.enc" --out "tailieu_giaima.pdf" --key 000102030405060708090a0b0c0d0e0f
```

Khi giải mã bắt buộc phải có `--out`. Nếu sai mật khẩu hoặc khóa, chương trình thường báo lỗi đệm PKCS#7 và thoát với mã lỗi 1.

### Các tùy chọn của `demo.py`

| Tùy chọn | Ý nghĩa |
|---|---|
| `--key <hex>` | Khóa 16 byte dạng hex (mặc định: khóa của FIPS 197 C.1) |
| `--password <chuỗi>` | Mật khẩu, dẫn xuất thành khóa 128-bit qua PBKDF2 |
| `--plaintext <hex>` | Bản rõ 16 byte dạng hex cho demo một khối |
| `--text <chuỗi>` | Văn bản UTF-8 cần mã hóa CBC |
| `--trace` | In State dạng ma trận qua từng bước |
| `--demo-zip` | Chạy kịch bản mã hóa/giải mã file ZIP mẫu |
| `--encrypt-file <đường dẫn>` | File cần mã hóa |
| `--decrypt-file <đường dẫn>` | File cần giải mã |
| `--out <đường dẫn>` | File đầu ra |

## Giới hạn

* **CBC chỉ bảo mật nội dung, không xác thực.** Bản mã bị sửa vẫn có thể giải mã ra dữ liệu sai mà không báo lỗi.
* **SHA-256 chỉ để đối chiếu sau khi giải mã**, không được lưu trong file `.enc` và không bảo vệ file khỏi bị sửa đổi.
* **Sai mật khẩu không phải lúc nào cũng bị phát hiện.** Khóa sai thường làm bước gỡ đệm báo lỗi, nhưng khoảng 1/256 trường hợp vẫn lọt qua và cho ra dữ liệu rác.
* **Hiệu năng thấp** (cỡ vài trăm KB/s do Python thuần), và file được đọc nguyên vào bộ nhớ.
* Chỉ hỗ trợ khóa 128 bit.

## Tài liệu tham khảo

1. NIST, **FIPS 197**: *Advanced Encryption Standard (AES)*, cập nhật 2023.
2. NIST, **SP 800-38A**: *Recommendation for Block Cipher Modes of Operation* (chế độ CBC), 2001.
3. IETF, **RFC 5652** mục 6.3: *Cryptographic Message Syntax* (đệm PKCS#7).
4. IETF, **RFC 8018**: *PKCS #5: Password-Based Cryptography Specification v2.1* (PBKDF2).
5. Joan Daemen và Vincent Rijmen, *The Design of Rijndael: AES - The Advanced Encryption Standard*, Springer.
6. Lucas Boppre Niehues (boppreh), *Pure Python AES implementation*, [boppreh/aes](https://github.com/boppreh/aes).
