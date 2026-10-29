# AES-128 — Tuần 2

Cài đặt phần mã hóa AES-128 bằng Python theo FIPS 197. Chương trình cho phép
theo dõi State và khóa vòng để đối chiếu từng bước với báo cáo.

## Chạy thử

Yêu cầu Python 3.10 trở lên. Không cần cài thêm thư viện.
Mở terminal trong thư mục chứa `aes.py` và `demo.py`, rồi chạy:

```sh
python demo.py
python demo.py --trace
python -m unittest -v
```

Ví dụ mặc định lấy từ FIPS 197 bản 2001, Phụ lục C.1:

```text
Plaintext : 00112233445566778899aabbccddeeff
Key       : 000102030405060708090a0b0c0d0e0f
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
FIPS C.1  : PASS
```

Nhập một khối hex hoặc một chuỗi mã hóa UTF-8 thành đúng 16 byte:

```sh
python demo.py --plaintext 00112233445566778899aabbccddeeff --key 000102030405060708090a0b0c0d0e0f --trace
python demo.py --text "AES week 2 demo!"
python demo.py --trace > demo_trace.txt
```

`--text` và `--plaintext` không dùng cùng lúc. Ký tự tiếng Việt có thể chiếm
nhiều byte; chương trình kiểm tra độ dài sau khi mã hóa UTF-8.
Ciphertext được in bằng hex, không giải mã thành chuỗi UTF-8.

## Đọc mã nguồn

1. Bắt đầu với `encrypt_block`: AddRoundKey ban đầu, 9 vòng đầy đủ, vòng cuối bỏ MixColumns.
2. Đọc `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key` để đối chiếu từng phép biến đổi.
3. Đọc `expand_key`: tạo 44 word, ghép thành 11 khóa K0 đến K10.
4. Xem `print_step` trong `demo.py` để hiểu cách vẽ State thành ma trận.

State lưu theo cột: `state[4 * column + row]`. Các phép biến đổi trả về `bytes`
mới. Callback `trace(round_number, step, value)` nhận một bản trạng thái bất biến;
không cần bật trace khi chỉ muốn lấy ciphertext.

```python
from aes import encrypt_block

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
ciphertext = encrypt_block(plaintext, key)
print(ciphertext.hex())
```

## Phạm vi và kiểm thử

Đợt này có mã hóa AES-128 một khối, mở rộng khóa và trace. Chưa có hàm giải mã,
padding, chế độ mã hóa nhiều khối hoặc giao thức truyền mạng. Các hàm biến đổi
cấp thấp giả định State hợp lệ; `encrypt_block` và `expand_key` kiểm tra đầu vào.

Bộ kiểm thử gồm 7 test method: 5 cặp plaintext/ciphertext chuẩn, toàn bộ 11 khóa
vòng, 40 trạng thái sau phép biến đổi (kể cả AddRoundKey ban đầu), phép xtime,
đầu vào sai và cách xử lý tham số dòng lệnh. Các giá trị kỳ vọng được chép từ
tài liệu NIST, không được sinh bằng chính hàm đang kiểm thử.

Đây là mã phục vụ học thuật: bảng tra S-box và Python không bảo đảm thời gian
thực thi hằng định. Khi bảo vệ dữ liệu thật, dùng thư viện mật mã đã được kiểm
chứng cùng chế độ phù hợp như AES-GCM. Trace hiển thị khóa và dữ liệu trung gian,
chỉ bật với khóa thử nghiệm. Việc khớp vector không phải chứng nhận FIPS.

## Nguồn

1. [NIST FIPS 197-upd1, cập nhật 09/05/2023](https://doi.org/10.6028/NIST.FIPS.197-upd1):
   định nghĩa thuật toán, S-box, phép toán trên byte và mở rộng khóa.
2. [FIPS 197 bản 2001, Phụ lục C.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf):
   ví dụ AES-128 và các giá trị trung gian. Bản này đã được thay thế; chỉ dùng làm
   nguồn dữ liệu ví dụ. Bản cập nhật 2023 không thay đổi thuật toán.
3. [NIST AES_Core128](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf):
   bốn cặp kiểm thử bổ sung. Từng khối được dùng độc lập để kiểm tra lõi AES;
   chương trình không triển khai chế độ ECB cho thông điệp nhiều khối.
