# Nmap Scans

Nmap là một công cụ tiêu chuẩn ngành để mapping network, xác định live hosts và khám phá các dịch vụ. Vì đây là một trong những công cụ quét mạng được sử dụng nhiều nhất nên nhà phân tích bảo mật phải xác định các mẫu mạng được tạo bằng công cụ đó. Phần này sẽ đề cập đến việc xác định các loại quét Nmap phổ biến nhất.

- TCP connect scans
- SYN scans
- UDP scans

## **TCP flags in a nutshell.**

| Notes | Wireshark Filters |
| --- | --- |
| Global search. | • tcp
• udp |
| • Only SYN flag. 
• SYN flag is set. Các bit còn lại ko quan trọng | • tcp.flags == 2
• tcp.flags.syn == 1 |
| • Only ACK flag. 
• ACK flag is set. Các bit còn lại ko quan trọng | • tcp.flags == 16
• tcp.flags.ack == 1 |
| • Only SYN, ACK flags.
• SYN and ACK are set. Các bit còn lại ko quan trọng. | • tcp.flags == 18
• (tcp.flags.syn == 1) and (tcp.flags.ack == 1) |
| • Only RST flag.
• RST flag is set. Các bit còn lại ko quan trọng | • tcp.flags == 4
• tcp.flags.reset == 1 |
| • Only RST, ACK flags.
• RST and ACK are set. Các bit còn lại ko quan trọng | • tcp.flags == 20
• (tcp.flags.reset == 1) and (tcp.flags.ack == 1) |
| • Only FIN flag
• FIN flag is set. Các bit còn lại ko quan trọng | • tcp.flags == 1
• tcp.flags.fin == 1 |

# **TCP Connect scans**

- Dựa vào bắt tay ba bước three-way handshake (cần kết thúc quá trình bắt tay).
- Thường được thực hiện bằng lệnh `nmap -sT`.
- Được sử dụng bởi người dùng không có đặc quyền non-privileged users (tùy chọn chỉ dành cho người dùng không root).
- Thường có kích thước cửa sổ lớn hơn 1024 byte vì yêu cầu cần một số dữ liệu do tính chất của giao thức.

| Open TCP Port | Open TCP Port | Closed TCP Port |
| --- | --- | --- |
| • SYN -->
• <-- SYN, ACK
• ACK --> | • SYN -->
• <-- SYN, ACK
• ACK -->
• RST, ACK --> | • SYN -->
• <-- RST, ACK |

The images below show the three-way handshake process of the open and close TCP ports. 

**Open TCP port (Connect):**

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/e78cb93c-652b-4a68-bfdc-8eaaf99701c3)

**Closed TCP port (Connect):**

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/a0f90081-70fa-4bb1-8618-b5fb51987888)

Không phải lúc nào cũng dễ phát hiện ra các mẫu patterns trong các capture file lớn. Do đó cần sử dụng bộ lọc chung để xem các mẫu bất thường ban đầu và sau đó dễ dàng tập trung vào lưu lượng truy cập cụ thể:

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/cb2627f7-f3e6-46fe-8591-46db8f0e0f7f)

# SYN Scans

- Không dựa vào bắt tay ba bước three-way handshake (không cần kết thúc quá trình bắt tay).
- Thường được thực hiện bằng lệnh `nmap -sS`.
- Được sử dụng bởi người dùng có đặc quyền privileged users
- Thường có kích thước nhỏ hơn hoặc bằng 1024 byte vì yêu cầu chưa kết thúc và không mong nhận được dữ liệu.

| Open TCP Port | Close TCP Port |
| --- | --- |
| • SYN -->
• <-- SYN,ACK
• RST--> | • SYN -->
• <-- RST,ACK |

**Open TCP port (SYN):**

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/f715577f-81df-47a9-a76b-11fe877038c5)

**Closed TCP port (SYN):**

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/1d3c8bdc-b373-408c-bb8b-8eeb9f7e81ab)

The given filter shows the TCP SYN scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/81298eee-994b-46a6-859e-99645724c45f)

# UDP

- Không yêu cầu quá trình bắt tay
- Không có lời nhắc mở cổng
- Thông báo lỗi ICMP khi đóng cổng
- Thường được thực hiện bằng lệnh `nmap -sU`.

| Open UDP Port | Closed UDP Port |
| --- | --- |
| • UDP packet --> | • UDP packet -->
• ICMP Type 3, Code 3 message. (Destination unreachable, port unreachable) |

**Closed (port no 69) and open (port no 68) UDP ports:**

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/d23c27ec-906d-40b6-8711-de2de299c423)

Hình ảnh trên cho thấy cổng đã đóng trả về gói lỗi ICMP. Thoạt nhìn không có thêm thông tin nào được cung cấp về lỗi, vậy làm cách nào nhà phân tích có thể quyết định thông báo lỗi này thuộc về đâu? Thông báo lỗi ICMP sử dụng yêu cầu ban đầu dưới dạng dữ liệu được đóng gói để hiển thị nguồn/lý do của gói. Khi mở rộng phần ICMP trong ngăn chi tiết gói, bạn sẽ thấy dữ liệu được đóng gói và yêu cầu ban đầu, như trong hình bên dưới.

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/8b35495a-1eb3-40dd-8e54-260a46d5d4e0)

The given filter shows the UDP scan patterns in a capture file.

`icmp.type==3 and icmp.code==3`

![image](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/5405d249-a3f7-47db-8411-2b9cf46b6760)

