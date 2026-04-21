# Phát Hiện Tấn Công Web Qua Log Bằng Machine Learning

## Mở đầu
Dự án này ứng dụng Học máy (Machine Learning), cụ thể là thuật toán **Random Forest Classifier**, để phân tích truy cập của người dùng thông qua log máy chủ web (như access log của Nginx/Apache). Mục đích là để nhận diện và phân loại các web request có dấu hiệu bất thường, từ đó phòng ngừa rủi ro bị tấn công (như SQL Injection, XSS, Path Traversal, OS Command Injection,...). Đây là mã nguồn phục vụ riêng cho bài Lab 08 & 09 thực hành an toàn thông tin.

## Chức năng cốt lõi
1. **Trích xuất đặc trưng (Feature Engineering):** Bóc tách URL web nhằm tìm kiếm các dấu hiệu lạ, bao gồm các từ khóa SQL độc hại, kịch bản Javascript, mã nguồn Command Line, các kỹ thuật leo thang thư mục (Path traversal), và tỉ lệ ký tự bị mã hóa (URL Encode).
2. **Kỹ thuật bơm dữ liệu (Data Augmentation):** Tự động mô phỏng và nhân bản thêm một số mẫu hình tấn công điển hình và request nhận diện bình thường, cung cấp thêm tri thức cho AI khỏi bị thiên kiến (bias classifier).
3. **Huấn luyện mô hình (Training):** Dạy mô hình AI học đặc tính phân biệt qua tập hợp dữ liệu tiêu chuẩn (CSIC 2010 Web Application Attacks benchmark dataset).
4. **Phân tích Log thực tế:** Dò quét qua các file chứa log hệ thống để in ra tỉ lệ xác suất (Predict Probability) mức rủi ro tấn công.

## Cấu trúc thư mục

* **`lab89.ipynb`**: File mã nguồn chính, triển khai toàn bộ quá trình: Load dữ liệu, chế biến đặc trưng (Feature extraction), train ML_model, in Confusion Matrix và phán đoán rủi ro trên logs.
* **`csic_database.csv/`**: Chứa dataset huấn luyện của tổ chức CSIC.
* **`access.log` / `testlog.log` / `test.log`**: File log thực tế hoặc tự giả lập, phục vụ quá trình test thử nghiệm của mô hình sau khi đã học xong.
* **`Bai0809_TH.docx`**: Tài liệu hướng dẫn thực hành/báo cáo lý thuyết liên quan đến bài tập.

## Yêu cầu môi trường và Hệ thống
Hệ thống cần cài đặt sẵn Python và Jupyter Notebook (hoặc sử dụng IDE như VS Code). Chạy lệnh sau để tải các thư viện:
```bash
pip install pandas scikit-learn matplotlib seaborn
```

## Hướng dẫn chạy và sử dụng

**Bước 1: Tải kho mã nguồn**
- Download mã nguồn này về thiết bị của bạn.
- Hãy kiểm tra và đảm bảo tập dữ liệu `csic_database.csv` được đặt đúng chuẩn đường dẫn (vd: `csic_database.csv/csic_database.csv`).

**Bước 2: Mở và chạy môi trường lập trình**
- Mở file `lab89.ipynb` trong Jupyter.
- Chạy lần lượt các block mã từ trên xuống dưới.

**Bước 3: Quy trình hệ thống trong Notebook**
- Block tiền xử lý sẽ thiết lập hàm `extract_features`, giúp dịch chuỗi URL text sang ma trận số hoá mà mô hình hiểu được.
- Block Training sẽ load toàn bộ dữ liệu CSIC và tạo object `RandomForestClassifier` (với thông số `n_estimators=300`).
- Ở phần in báo cáo kết quả, đồ thị Histogram và Confusion Matrix sẽ thể hiện tổng quan Accuracy (Độ chính xác kì vọng > 90%).
- Khối code cuối **Kiểm tra thực tế** sẽ tự động phân tách file `access.log` và `testlog.log`, xuất thẳng kết quả ra giao diện xem đâu là: `[Normal]` an toàn và đâu là `[Attack]` nguy hiểm.

## Tiêu chí đánh giá Model (Threshold)
- Hệ thống cố tình sử dụng `threshold = 0.35` thay vì `0.5` mặc định.
- Hành động này ưu tiên việc bắt nhầm thay vì bỏ sót (tăng chỉ số **Recall** lên ~0.94), rất phù hợp với bối cảnh triển khai hệ thống NIDS chặn đứng các đợt tấn công từ sớm. Tránh nguy cơ mô hình quá bảo thủ bỏ qua các requests tinh vi.
