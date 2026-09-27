sudo python3 wg_dashboard.py --bind 0.0.0.0 --port 8080 --interval 5 --names /etc/wireguard/peers.txt




#fill up the /etc/wireguard/peers.txt with this format:


 sudo cat /etc/wireguard/peers.txt
# /etc/wireguard/peers.txt
# <peer preshared key>=<friendly name

FxANxC7uL2HQliSMywTn3pyrrCFwtXbJiAsukiHuxHE==10Ultra
lxxmuPGiWoKtP2fKmt9cBPpGgFc/bY7wV7c1zZnd2Rc==S23Ultra
4s0CxKLLDU/MKbEjnonORDIKLnztP/YO5GofylFP6C8==Nashat
ZvhoeR7r2QvXsyzPxi9984GwkQN2Pr1rjFTVYszjRnQ==Namarek
0mx5XWJKV2jMbrWnHLnCsu5zawdX+DauiIXPXj63K1E==Ismail
3JX6QfTgfyXLt2kBl5OaCSkdEVEe404o6AA5YrP9RHE==AnasOman
OWgjRODs49TY9hCRJDUMJ+WduT46SWyoM5jarD5Pbnk==SalehHasasneh
isFC/xq3tNDh7AwUdI0gY8CvSicaPp9xRYa9KsW1iVM==AbdallahHamadneh
NU320xDcwuzg6yUtMcfSDKROVY8GqMHCNWMvL3ZOWQ0==Marwan1
GpnpQjXVvacd6AtlHQ8I1pWK2rvSLzifcCBozjFDnFY==Marwan2


sudo wg show all dump
wg0     8FkDQK44nw5adqbABaq/Q84MozOxZRfRHGdynzmgDWI=    WTHGTADBIQQuP6ereY5DrNzYeHwUwKR1B7NYDxpMRH0=    50452   off
wg0     lxxmuPGiWoKtP2fKmt9cBPpGgFc/bY7wV7c1zZnd2Rc=    z735h57yKkf/hBhLZ8V7T+PEzYSR/UHGiR5235bUv3k=    (none)  10.66.66.2/32,fd42:42:42::2/128 0       0       0       off
wg0     FxANxC7uL2HQliSMywTn3pyrrCFwtXbJiAsukiHuxHE=    +8++HSo/PT3A6BTpy5oIt35m+dyqb/qX5ru7m0xJXNg=    45.155.47.233:40072     10.66.66.3/32,fd42:42:42::3/128 1788936563      27839780        474427368       off
wg0     ZvhoeR7r2QvXsyzPxi9984GwkQN2Pr1rjFTVYszjRnQ=    FLAp8VKTUL189xN0rKdMprG1rrbCUEeKxFt0kmQjo2o=    45.155.47.233:29607     10.66.66.4/32,fd42:42:42::4/128 1788936604      103630680       1329630252      off
wg0     0mx5XWJKV2jMbrWnHLnCsu5zawdX+DauiIXPXj63K1E=    kc7pKdGVamw/0ZdsIcy2jT1Gb7kGQLgyEtMJRZmh854=    45.155.47.233:53814     10.66.66.5/32,fd42:42:42::5/128 1788936638      153397112       2577977124      off
wg0     NU320xDcwuzg6yUtMcfSDKROVY8GqMHCNWMvL3ZOWQ0=    7PGrcjY2fiW9IWuBg//68JVFm84I0CpVHU45rhU1M74=    (none)  10.66.66.6/32,fd42:42:42::6/128 0       0       0       off
wg0     GpnpQjXVvacd6AtlHQ8I1pWK2rvSLzifcCBozjFDnFY=    u2giK6HCQdAyMg1Y9w+xgBMZMBrmPPlyw8SyPRTDRJo=    (none)  10.66.66.7/32,fd42:42:42::7/128 0       0       0       off
wg0     OWgjRODs49TY9hCRJDUMJ+WduT46SWyoM5jarD5Pbnk=    Cyi4SRySjJFao8Gb4HUw3US/FbP1DeUiGmb+BCf/HXg=    (none)  10.66.66.8/32,fd42:42:42::8/128 0       0       0       off
wg0     3JX6QfTgfyXLt2kBl5OaCSkdEVEe404o6AA5YrP9RHE=    SrozMzPEtEAGP07b/QfR3UuM9yiCwLql7xoWtSE/jyk=    5.162.9.104:50656       10.66.66.9/32,fd42:42:42::9/128 1788936538      44792860        781523700       off
wg0     4s0CxKLLDU/MKbEjnonORDIKLnztP/YO5GofylFP6C8=    HvIxZuQ4exu5wko7LbsmcW1k3J8oHaMy4/2Oo7wudU4=    (none)  10.66.66.10/32,fd42:42:42::10/128       0       0       0       off
wg0     isFC/xq3tNDh7AwUdI0gY8CvSicaPp9xRYa9KsW1iVM=    QJ8sygF0GujmT2nV3r7dHoyTdoU9xTsAkXL4Q5BQvQ4=    (none)  10.66.66.11/32,fd42:42:42::11/128       0       0       0       off