
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