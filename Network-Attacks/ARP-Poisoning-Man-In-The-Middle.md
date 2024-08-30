# ARP Poisoning & Man In The Middle!

# ARP

**ARP** giao thức **A**ddress **R**esolution **P**rotocol (**ARP**), là công nghệ chịu trách nhiệm cho phép các thiết bị tự nhận dạng trên mạng. Address Resolution Protocol Poisoning (còn được gọi là tấn công ARP Spoofing hoặc Man In The Middle (MITM)) là một loại tấn công liên quan đến việc gây nhiễu/thao túng mạng bằng cách gửi các gói ARP độc hại đến cổng mặc định. Mục đích cuối cùng là thao túng **"bảng địa chỉ IP tới MAC"** và truy ra lưu lượng truy cập của máy chủ mục tiêu.

**Tóm tắt phân tích ARP:**

- Hoạt động trên mạng cục bộ
- Cho phép liên lạc giữa các địa chỉ MAC
- Không phải là một giao thức an toàn
- Không phải là một giao thức có thể định tuyến
- Nó không có chức năng xác thực
- Các dạng phổ biến là yêu cầu và phản hồi, thông báo và các gói tin vô cớ.

| Notes | Wireshark filter |
| --- | --- |
| Global search | • arp |
| "ARP" options for grabbing the low-hanging fruits:
• Opcode 1: ARP requests.
• Opcode 2: ARP responses.
• Hunt: Arp scanning
• Hunt: Possible ARP poisoning detection
• Hunt: Possible ARP flooding from detection: | • arp.opcode == 1
• arp.opcode == 2
• arp.dst.hw_mac==00:00:00:00:00:00
• arp.duplicate-address-detected or arp.duplicate-address-frame
• ((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address) |
![1](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/0dfb4daa-bd95-46ca-8c7a-36b172a19912)


Một tình huống đáng ngờ  là có hai phản hồi (xung đột) ARP khác nhau cho một địa chỉ IP cụ thể. Trong trường hợp đó, tab thông tin của Wireshark sẽ cảnh báo . Tuy nhiên, nó chỉ hiển thị lần xuất hiện thứ hai của giá trị trùng lặp để làm nổi bật xung đột. . Một trường hợp giả mạo IP có thể xảy ra được hiển thị trong hình bên dưới.
![2](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/7fc14b91-6582-46eb-a1f3-ccb44bf246b6)


Ở đây, việc biết kiến trúc mạng và kiểm tra lưu lượng truy cập trong một khung thời gian cụ thể có thể giúp phát hiện sự bất thường.   Nhìn vào bức ảnh đã cho; có xung đột; địa chỉ MAC kết thúc bằng "b4" đã tạo yêu cầu ARP bằng địa chỉ IP "192.168.1.25", sau đó xác nhận là có địa chỉ IP "192.168.1.1".

| Notes | Detection Notes | Findings |
| --- | --- | --- |
| Possible IP address match. | 1 IP address announced from a MAC address. | • MAC: 00:0c:29:e2:18:b4
• IP: 192.168.1.25 |
| Possible ARP spoofing attempt. | 2 MAC addresses claimed the same IP address (192.168.1.1).The " 192.168.1.1" IP address is a possible gateway address. | • MAC1: 50:78:b3:f3:cd:f4
• MAC 2: 00:0c:29:e2:18:b4 |
| Possible ARP flooding attempt. | The MAC address that ends with "b4" claims to have a different/new IP address. | • MAC: 00:0c:29:e2:18:b4
• IP: 192.168.1.1 |

Hãy tiếp tục kiểm tra lưu lượng truy cập để phát hiện bất kỳ điểm bất thường nào khác. Lưu ý vụ án được chia thành nhiều file chụp để việc điều tra dễ dàng hơn.
![3](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/9c35ea19-f3e0-4efb-9b6a-92d06fd39897)


Lúc này, rõ ràng là có sự bất thường. hàng loạt yêu cầu ARP. Đây có thể là hoạt động độc hại, quá trình quét hoặc sự cố mạng. Có một điều bất thường mới; địa chỉ MAC kết thúc bằng "b4" đã tạo nhiều yêu cầu ARP bằng địa chỉ IP "192.168.1.25". Hãy tập trung vào nguồn gốc của sự bất thường này và mở rộng các ghi chú đã ghi.

| Notes | Detection Notes | Findings |
| --- | --- | --- |
| Possible IP address match. | 1 IP address announced from a MAC address. | • MAC: 00:0c:29:e2:18:b4
• IP: 192.168.1.25 |
| Possible ARP spoofing attempt. | 2 MAC addresses claimed the same IP address (192.168.1.1).The " 192.168.1.1" IP address is a possible gateway address. | • MAC1: 50:78:b3:f3:cd:f4
• MAC 2: 00:0c:29:e2:18:b4 |
| Possible ARP spoofing attempt. | The MAC address that ends with "b4" claims to have a different/new IP address. | • MAC: 00:0c:29:e2:18:b4
• IP: 192.168.1.1 |
| Possible ARP flooding attempt. | The MAC address that ends with "b4" crafted multiple ARP requests against a range of IP addresses. | • MAC: 00:0c:29:e2:18:b4
• IP: 192.168.1.xxx |

Cho đến thời điểm này, rõ ràng là địa chỉ MAC kết thúc bằng "b4" sở hữu địa chỉ IP "192.168.1.25" và tạo ra các yêu cầu ARP đáng ngờ đối với một loạt địa chỉ IP. Nó cũng tuyên bố có địa chỉ cổng có thể có. Hãy tập trung vào các giao thức khác và phát hiện sự phản ánh của sự bất thường này trong các phần sau của khung thời gian.

![4](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/2e309f99-7f0c-49d1-9e32-6f4374962db3)

Đây là lưu lượng truy cập HTTP và mọi thứ đều có vẻ bình thường ở cấp độ IP nên không có thông tin liên kết nào với những phát hiện trước đây. Hãy thêm địa chỉ MAC dưới dạng cột trong ngăn danh sách gói để hiển thị thông tin liên lạc đằng sau địa chỉ IP.
![5](https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/assets/139641711/8a4dd1cf-e43f-49a1-941e-b9bfef96cede)


Thêm một điều bất thường nữa! Địa chỉ MAC kết thúc bằng "b4" là đích đến của tất cả các gói HTTP! Rõ ràng là có một cuộc tấn công MITM và kẻ tấn công là máy chủ có địa chỉ MAC kết thúc bằng "b4". Tất cả lưu lượng truy cập được liên kết đến địa chỉ IP "192.168.1.12" sẽ được chuyển tiếp đến máy chủ độc hại. Hãy tóm tắt những phát hiện trước khi kết thúc cuộc điều tra.
