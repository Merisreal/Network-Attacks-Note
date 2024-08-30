
## ARP Spoofing & Abnormality Detection

#### ARP Spoofing
Address Resolution Protocol (ARP): thường bị lợi dụng để Man-in-the-middle  và denial-of-service attacks 

Key để tìm ARP Spoofing:
Wireshark:
```
arp.opcode

opcode == 1: all ARP request
opcode == 2: all ARP replies
```

![[Pasted image 20240820135441.png]]

Để sàn lọc nhiều hơn
```
arp.duplicate-address-detected && arp.opcode == 2
```

Tuy nhiên ta cần xác định được IP gốc -> Tìm ra thiết bị thay đổi ip thông qua Mac spoofing

```
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
```

![[Pasted image 20240820142634.png]]

Trong trường hợp này, chúng ta có thể ngay lập tức nhận thấy rằng địa chỉ MAC 08:00:27:53:0c

ban đầu được liên kết với địa chỉ IP 192.168.10.5, nhưng gần đây đã chuyển sang 192.168.10.4 -> ARP spoofing hoặc làm nhiễu cache.

#### ARP Scanning 

1 vài cách nhận dạng ARP Scanning

1. `Broadcast ARP requests sent to sequential IP addresses (.1,.2,.3,...)`
    
2. `Broadcast ARP requests sent to non-existent hosts`
    
3. `Potentially, an unusual volume of ARP traffic originating from a malicious or compromised host`

#### Findding ARP scanning
```
arp.opcode
```

![[Pasted image 20240823093702.png]]

=>Các hosts đang  phản hồi các yêu cầu ARP của chúng -> Attacker đã thực hiện thành công việc thu nhập thông tin 

#### Identifying Denial-of-Service
![[Pasted image 20240823094059.png]]
=> Ngay lập tức, chúng tôi có thể lưu ý rằng lưu lượng ARP của kẻ tấn công có thể chuyển trọng tâm sang việc khai báo địa chỉ MAC mới cho all live IP addresses. Mục đích ở đây là làm hỏng ARP cache của bộ định tuyến
![[Pasted image 20240823094239.png]]

-> Ngược lại, chúng ta có thể chứng kiến ​​việc phân bổ trùng lặp 192.168.10.1 cho các thiết bị khách. Điều này cho thấy kẻ tấn công đang cố gắng làm hỏng ARP cachecủa các thiết bị nạn nhân này với mục đích cản trở lưu lượng truy cập theo cả hai hướng


## 802.11 Denial of Service

#### How Deauthentication Attacks Work

Thường thực hiện ở **link-layer**, attacker thường dùng để:
+ Thu nhập WPA handshake -> offline dictionary attack
+ Dos
+ Để buộc người dùng ngắt kết nối khỏi mạng của chúng ta và có thể kết nối với mạng của kẻ tấn công nhằm thu thập thông tin
-> Attacker sẽ giả mạo một khung Deauthentication 802.11 trông như xuất phát từ điểm truy cập legit -> sau đó ngắt kết nối mạng thiết bị ra khỏi mạng -> thường thì thiết bị sẽ kết nối lại và thực hiện quy trình handshake trong khi attacker đang sniffing 
![[Pasted image 20240823100744.png]]Attacker giả mạo hoặc thay đổi địa chỉ MAC của frame'sender. client không thể thực sự phân biệt được sự khác nhau nếu không có các biện pháp kiểm soát bổ sung như IEEE 802.11w (Management Frame Protection). Mỗi yêu cầu deauthentication đều đi kèm với một mã lý do (reason code) để giải thích lý do tại sao thiết bị khách bị ngắt kết nối.

Trong hầu hết các trường hợp, các công cụ cơ bản như **aireplay-ng và mdk4** sử dụng mã lý do **7** để thực hiện deauthentication.

REASON CODE: https://support.zyxel.eu/hc/en-us/articles/360009469759-What-is-the-meaning-of-802-11-Deauthentication-Reason-Codes

#### Finding Deauthentication Attacks

Cheatsheet: https://semfionetworks.com/wp-content/uploads/2021/04/wireshark_802.11_filters_-_reference_sheet.pdf


limit i lưu lượng truy cập từ BSSID (MAC) của AP in wireshark:
```
 wlan.bssid == xx:xx:xx:xx:xx:xx
```

Giả sử chúng ta muốn xem xét các khung hủy xác thực từ BSSID của chúng ta hoặc kẻ tấn công giả vờ gửi những khung này từ BSSID của chúng ta, chúng ta có thể sử dụng bộ lọc Wireshark sau:
```
(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```

![[Pasted image 20240823101626.png]]

![[Pasted image 20240823101632.png]]

 Nhiều khung hủy xác thực đã được gửi đến một trong các thiết bị  client -> dấu hiệu của cuộc tấn công. Ngoài ra, nếu i mở các tham số cố định trong quản lý không dây,  ta thấy reason code = 7 (aireplay-ng,mkd4)
 ![[Pasted image 20240823101758.png]]


```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```

![[Pasted image 20240823101831.png]]
#### Revolving Reason Codes
Tuy nhiên  tinh vi hơn có thể cố gắng né tránh dấu hiệu rõ ràng này bằng cách thay đổi liên tục reason code. Attacker có thể cố gắng tránh bất kỳ cảnh báo nào có thể được kích hoạt bởi hệ thống phát hiện xâm nhập không dây (wireless intrusion detection system) bằng cách thay đổi reason code sau một thời gian nhất định.

-> Mẹo để phát hiện kỹ thuật này là tăng dần reason code như cách mà một script của kẻ tấn công sẽ làm. Chúng ta sẽ bắt đầu với mã lý do 1.

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 1)
```


```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 2)
```
.....

-> Khó giải quyết lắm nên phải có biện pháp:

1. `Enable IEEE 802.11w (Management Frame Protection) if possible`
2. `Utilize WPA3-SAE`
3. `Modify our WIDS/WIPS detection rules`


#### Finding Failed Authentication Attempts

Giả sử attacker cố gắng kết nối với mạng không dây  -> có thể nhận thấy có quá nhiều yêu cầu liên kết đến từ một thiết bị. Để lọc những thứ này, chúng ta có thể sử dụng như sau.

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11)
```


## Rogue Access Point & Evil-Twin Attacks

Đối với các access points độc hại, rogue và evil-twin attacks -> nổi nhất
![[Pasted image 20240823154653.png]]
#### Rogue Access Points
Rogue Access Points là mạng WIFI giả mạo (clone) có các thông số giống hệt một WIFI mục tiêu. Rogue Access Points do Hacker tạo ra để lừa người dùng kết nối vào, sau đó thực hiện đánh cắp mật khẩu hoặc các thông tin cá nhân khác

-> Khi 2 mạng có cùng SSID, thiết bị sẽ ưu tiên mạng nào có tín hiện mạnh nhất và nhìn thấy đầu tiên -> Hacker có thể giả dạng một điểm truy cập có cùng SSID mặc định -> có thể dùng tool như airmon-ng để tìm ssid 
#### Evil Twin

![[Pasted image 20240823160003.png]]


#### Airodump-ng Detection

```
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```
wlan.fc.type_subtype == 8 : lọc beacon và phân tích phần Robust Security Network (RSN)
Thông thường một AP legit sẽ có phần RSN đầy đủ các AES, TKIP, PSK
![[Pasted image 20240823161807.png]]

Còn với AP not Legit thì sẽ ko có
![[Pasted image 20240823161820.png]]


Sau khi xác định được AP nào là mối đe dọa -> cần xác định xem User nào đã bị 'nhập' :))) 

```
(wlan.bssid == F8:14:FE:4D:E6:F2)
```
![[Pasted image 20240823161929.png]]

Nếu chúng ta phát hiện các ARP requests phát sinh từ một client device kết nối với mạng nghi ngờ, chúng ta có thể xác định đây là một chỉ báo tiềm năng của việc bị xâm phạm. Trong các trường hợp như vậy, chúng ta nên ghi lại các thông tin liên quan về client device để tiến hành các nỗ lực phản ứng sự cố tiếp theo.![[Pasted image 20240823162026.png]]
