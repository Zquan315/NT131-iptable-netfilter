# Linux kernel networking: Netfilter, IPTables, flows of application data packets via TCP/IP protocol stackt

## 1. Tóm tắt
Netfilter là một framework mạnh mẽ trong Linux kernel, cho phép lọc, theo dõi
và thao tác các gói tin mạng khi chúng đi qua hệ thống. Nó hoạt động tại các
điểm hook trong stack TCP/IP, cung cấp cơ chế để thay đổi hoặc loại bỏ gói tin
dựa trên các quy tắc xác định. IPTables là công cụ giao diện người dùng để
tương tác với Netfilter, giúp quản trị viên thiết lập các quy tắc tường lửa, NAT,
và chuyển tiếp gói tin, kiểm soát luồng dữ liệu vào, ra và qua hệ thống. Gói tin
ứng dụng được truyền tải thông qua các tầng của giao thức TCP/IP, trong đó
tầng mạng đảm bảo định tuyến, tầng transport (như TCP hoặc UDP) đảm bảo
kết nối và độ tin cậy, trước khi dữ liệu được đóng gói và truyền qua các
interface mạng. Các cơ chế này giúp duy trì an ninh và hiệu suất mạng trong
các hệ thống Linux.

#### Kiến trúc netfilter
![netfilter](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSJJRj8tEzAjJR0SCbKtNzh5NZo4htSYacMFA&s)

#### Kiến trúc iptables
![iptables](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcREMbYKbxtluDzxnkgMphl2qh2ptjhjqHcFwg&s)

### Kịch bản thực hiện: ###
- Hook LOCAL_IN - Giới hạn số lượng kết nối SSH (Chỉ có 1 kết nối bất kỳ)
- Chặn các máy muốn ping hoặc telnet đến một host cụ thể (10.0.3.8)
- Chặn các gói tin từ một địa chỉ IP nhất định khi cố gắng truy cập Apache port 80 trên máy chủ.
- Chặn truy cập Internet
- Ghi log và gửi cảnh báo về mail khi bị scanning port
- Từ chối mọi kết nối chỉ giữ lại ping
- Chống DOS
## 3. Triển khai
Nội dung triển khai, các bước thực hiện được nằm trong file PDF
## 4. Kết luận
- Trong báo cáo này, nhóm đã nghiên cứu và tìm hiểu về khái niệm, vai trò, và
các thành phần cơ bản của Iptables và Netfilter, bao gồm các loại bảng, chain,
và target của Iptables cũng như các hook quan trọng của Netfilter. Việc ứng
dụng các kịch bản thực tế cho thấy hiệu quả của Netfilter và Iptables trong việc
thiết lập các quy tắc bảo mật, quản lý lưu lượng mạng, và ngăn chặn các tấn
công mạng phổ biến như DoS và DDoS.36
Việc nắm vững mô hình TCP/IP và cách thức hoạt động của Netfilter giúp
nâng cao khả năng bảo mật và hiệu suất mạng của hệ thống. Từ những kiến
thức này, nhóm đã triển khai thành công nhiều kịch bản thực tế, đóng góp vào
việc nâng cao an ninh mạng cho hệ thống Linux.
- Trong tương lai, có thể mở rộng nghiên cứu và ứng dụng các công nghệ mới
như nftables hoặc tiến sâu hơn vào các khái niệm mạng phức tạp hơn như SDN
(Software Defined Networking) để tối ưu hóa và bảo vệ mạng
> Nội dung được thực hiện bởi nhóm 1 - Nhóm trưởng: Tô Công Quân
