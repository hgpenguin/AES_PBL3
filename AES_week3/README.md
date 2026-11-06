# Tuần 3 - Học phần PBL3

Dự án cài đặt và nghiên cứu chuẩn mã hóa nâng cao **AES-128 (Advanced Encryption Standard)**.
---

## Điểm mới của tuần 3

Kế thừa kết quả khảo sát lý thuyết ở Tuần 2, phiên bản **Tuần 3** được cập nhật:
1. **Kiến trúc Ma trận 2D trực quan (`class AES`):**
   * Tham khảo cấu trúc State ma trận $4 \times 4$ (`s[col][row]`) dễ hiểu và trực quan từ `boppreh/aes`.
   * Tối ưu hóa phép nhân cột `mix_columns` và `inv_mix_columns` theo công thức đại số của sách *The Design of Rijndael*.
   * Đóng gói hướng đối tượng: `aes = AES(key)`.
2. **Cơ chế tự động sinh khóa & Dẫn xuất khóa (Key Derivation):**
   * Sinh khóa ngẫu nhiên an toàn bằng CSPRNG của hệ điều hành (`os.urandom(16)`).
   * Cho phép người dùng nhập mật khẩu văn bản (passphrase) và tự động tạo khóa 128-bit qua hàm dẫn xuất chuẩn `PBKDF2-HMAC-SHA256`.
3. **Cơ chế đệm dữ liệu chuẩn PKCS#7:**
   * Cho phép mã hóa chuỗi byte có độ dài bất kỳ (tự động thêm đệm từ 1 đến 16 byte).
   * Kiểm tra tính hợp lệ nghiêm ngặt khi gỡ đệm (`unpad`), tự động phát hiện dữ liệu lỗi.
4. **Chế độ hoạt động CBC (Cipher Block Chaining):**
   * Mã hóa chuỗi khối kết hợp Vector khởi tạo ngẫu nhiên (**IV** 16 byte), loại bỏ hoàn toàn hiện tượng lộ mẫu dữ liệu (pattern leakage) của chế độ ECB.
5. **Mã hóa & Giải mã File / ZIP đa năng:**
   * Hỗ trợ mã hóa mọi định dạng file máy tính: `.zip`, `.pdf`, `.docx`, `.png`, `.txt`.
   * Cấu trúc file mã hóa chuẩn: `[16 bytes IV] + [Ciphertext CBC]`.
   * Kiểm chứng tính toàn vẹn 100% từng bit thông qua việc so khớp mã băm **SHA-256** trước và sau giải mã.


## Hướng dẫn chạy

### 1. Chạy kiểm thử tự động (Unit Tests)
```bash
python -m unittest -v test_aes.py
```
---

### 2. Chạy Demo tương tác (`demo.py`)

#### A. Demo mã hóa 1 khối chuẩn NIST FIPS 197 C.1:
```bash
python demo.py
```
*(Thêm cờ `--trace` nếu muốn xem chi tiết ma trận $4 \times 4$ qua từng bước biến đổi).*
```bash
python demo.py --trace
```

#### B. Demo mã hóa văn bản dài bất kỳ với mật khẩu (CBC + PKCS#7):
```bash
python demo.py --text "Học phần PBL3 Mạng máy tính" --password "MatKhauBaoMat@2026"
```

#### C. Demo tự động mã hóa & giải mã File ZIP thực tế (Kiểm chứng SHA-256):
```bash
python demo.py --demo-zip
```
Lệnh này sẽ tự động:
1. Tạo file nén `sample_archive.zip` chứa 2 tài liệu thực tế.
2. Mã hóa sang `sample_archive.zip.enc` bằng AES-128-CBC.
3. Giải mã khôi phục `sample_archive_recovered.zip`.
4. So sánh mã băm SHA-256 trước và sau giải mã $\rightarrow$ Xác nhận khớp 100%.
5. Mở file ZIP và đọc trích xuất trực tiếp nội dung bên trong.

#### D. Mã hóa và giải mã file cụ thể tùy chọn:
* **Mã hóa file:**
  ```bash
  python demo.py --encrypt-file "tailieu.pdf" --out "tailieu.pdf.enc" --password "MySecretPass"
  ```
* **Giải mã file:**
  ```bash
  python demo.py --decrypt-file "tailieu.pdf.enc" --out "tailieu_giaima.pdf" --password "MySecretPass"
  ```

---

## Tài liệu tham khảo
1. **NIST FIPS 197**: *Advanced Encryption Standard (AES)*, U.S. National Institute of Standards and Technology.
2. **Joan Daemen & Vincent Rijmen**: *The Design of Rijndael: AES - The Advanced Encryption Standard*, Springer.
3. **Lucas Boppre**: *Pure Python AES implementation*, [boppreh/aes](https://github.com/boppreh/aes).
