description= [[
Skripta skenira određene hostove te vrati informaciju o tome koliko uređaja koristi koji operativni sustav.
Skripta služi kao primjer kako skenirati sa određenim host pravilom te pokazuje kako koristiti nmap.registry koji može služiti i za komunikaciju između različitih skripti.
NAPOMENA: moglo se koristiti i postrule kako bi tek na kraju dobili konacni rezltat, a ne nakon svakog skeniranog hosta.

Mentored under:
--FOI OSS--
-Faculty of Organisation and Informatics  - Open Systems and Security -
http://security.foi.hr/wiki/index.php/Glavna_stranica
Tonimir Kišasondi
]]

---
--@usage
--nmap -F -O --script os-sum.nse 192.168.1.1-25
--
--@output
--Host script results:
--| os-sum: 
--| 0 Mac device(s)
--| 1 Windows device(s)
--|_0 Linux device(s)
---

author = "Renato Turić"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

--kreiranje vlastitih vrijednosti unutar registra nmap.registry
nmap.registry.winNum = 0
nmap.registry.linuxNum = 0
nmap.registry.macNum = 0

--host pravilo koje u će pokrenuti action samo u onom slučaju ako je nmap mogao uspješno (OS perfect match) odrediti koji je OS na hostu, jer samo tada se rezultati spremaju unutar host.os tablice.
function hostrule(host, port)
  if host.os ~= nil then
		return true
	end
end

--funkcija action zbraja koliko se puta koji OS pojavio tijekom skeniranja
function action(host, port)
	
	--string.match provjerava da li unutar host.os tablice postoji OS sa kljucnom rijecju Windows, ako postoji onda se brojac u registru povecava za jedan
	if string.match(host.os[1].name,"Windows") then
		nmap.registry.winNum = nmap.registry.winNum + 1
	end
	--string.match provjerava da li unutar host.os tablice postoji OS sa kljucnom rijecju Mac, ako postoji onda se brojac u registru povecava za jedan
	if string.match(host.os[1].name,"Mac") then
		nmap.registry.macNum = nmap.registry.macNum + 1
	end
	--string.match provjerava da li unutar host.os tablice postoji OS sa kljucnom rijecju Linux, ako postoji onda se brojac u registru povecava za jedan
	if string.match(host.os[1].name,"Linux") then
		nmap.registry.linuxNum = nmap.registry.linuxNum + 1
	end
	
	--ispis rezultata
	return "\n".. tostring(nmap.registry.macNum) .. " Mac device(s)\n".. tostring(nmap.registry.winNum) .. " Windows device(s)\n" .. tostring(nmap.registry.linuxNum) .. " Linux device(s)"
end
