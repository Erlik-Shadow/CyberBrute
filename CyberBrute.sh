#!/bin/bash

# =============================================================================
# BruteForceMaster.sh - Nihai Şifre Kırma Aracı
# Oluşturan: Murat
# Bağlı Ekip: Ulyon Cyber Team
# Sürüm: 1.0 (14 Eylül 2025)
# Açıklama: Arşiv şifrelerini, hash tanımlamayı ve kırmayı destekleyen menü tabanlı

# Renkler (Cyberpunk Neon Paleti)
NEON_GREEN='\033[38;2;0;255;0m'
NEON_PURPLE='\033[38;2;255;0;255m'
NEON_CYAN='\033[38;2;0;255;255m'
DARK_GRAY='\033[38;2;28;37;38m'
NC='\033[0m' # Renk sıfırlama

# Rapor dosyası
# Güvenli rapor dizini (varsayılan)
REPORT_DIR="${HOME}/.local/share/cyberbrute"
mkdir -p "$REPORT_DIR"

# Rapor dosyası
REPORT_FILE="$REPORT_DIR/cyberbrute_report_$(date +%F_%H-%M-%S).txt"
echo "CyberBrute v2 Raporu - $(date)" > "$REPORT_FILE"

VERBOSE=1  # 1: açık, 0: sessiz
...
[[ $VERBOSE -eq 1 ]] && echo -e "${NEON_CYAN}Deneniyor: $password${NC}"


# Gerekli araçları kontrol et
check_tools() {
    command -v unzip >/dev/null 2>&1 || { echo -e "${NEON_PURPLE}Hata: unzip yüklü değil!${NC}"; exit 1; }
    command -v unrar >/dev/null 2>&1 || { echo -e "${NEON_PURPLE}Hata: unrar yüklü değil!${NC}"; exit 1; }
    command -v pdftk >/dev/null 2>&1 || { echo -e "${NEON_PURPLE}Uyarı: pdftk yüklü değil, PDF kırma çalışmaz!${NC}"; }
    command -v openssl >/dev/null 2>&1 || { echo -e "${NEON_PURPLE}Hata: openssl yüklü değil!${NC}"; exit 1; }
}
# Hash tanımlayıcı (Güncellenmiş)
identify_hash() {
    local hash=$1
    echo -e "${NEON_CYAN}Hash analizi başlıyor...${NC}"
    echo "Hash analizi: $hash" >> "$REPORT_FILE"

    # MD5 (32 hex küçük)
    if [[ ${#hash} -eq 32 && $hash =~ ^[0-9a-f]{32}$ ]]; then
        echo -e "${NEON_GREEN}Hash: MD5 olarak tanımlandı.${NC}"
        echo "Sonuç: MD5 tespit edildi" >> "$REPORT_FILE"
    # NTLM (32 hex büyük)
    elif [[ ${#hash} -eq 32 && $hash =~ ^[0-9A-F]{32}$ ]]; then
        echo -e "${NEON_GREEN}Hash: NTLM olarak tanımlandı.${NC}"
        echo "Sonuç: NTLM tespit edildi" >> "$REPORT_FILE"
    # SHA1 (40 hex)
    elif [[ ${#hash} -eq 40 && $hash =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo -e "${NEON_GREEN}Hash: SHA1 olarak tanımlandı.${NC}"
        echo "Sonuç: SHA1 tespit edildi" >> "$REPORT_FILE"
    # SHA224 (56 hex)
    elif [[ ${#hash} -eq 56 && $hash =~ ^[0-9a-fA-F]{56}$ ]]; then
        echo -e "${NEON_GREEN}Hash: SHA224 olarak tanımlandı.${NC}"
        echo "Sonuç: SHA224 tespit edildi" >> "$REPORT_FILE"
    # SHA256 (64 hex)
    elif [[ ${#hash} -eq 64 && $hash =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo -e "${NEON_GREEN}Hash: SHA256 olarak tanımlandı.${NC}"
        echo "Sonuç: SHA256 tespit edildi" >> "$REPORT_FILE"
    # SHA384 (96 hex)
    elif [[ ${#hash} -eq 96 && $hash =~ ^[0-9a-fA-F]{96}$ ]]; then
        echo -e "${NEON_GREEN}Hash: SHA384 olarak tanımlandı.${NC}"
        echo "Sonuç: SHA384 tespit edildi" >> "$REPORT_FILE"
    # SHA512 (128 hex)
    elif [[ ${#hash} -eq 128 && $hash =~ ^[0-9a-fA-F]{128}$ ]]; then
        echo -e "${NEON_GREEN}Hash: SHA512 olarak tanımlandı.${NC}"
        echo "Sonuç: SHA512 tespit edildi" >> "$REPORT_FILE"
    # bcrypt (60 karakter, $2a|2b|2y$<cost>$<salt+hash>)
    elif echo "$hash" | grep -Eq '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'; then
        echo -e "${NEON_GREEN}Hash: bcrypt olarak tanımlandı.${NC}"
        echo "Sonuç: bcrypt tespit edildi" >> "$REPORT_FILE"
    else
        echo -e "${NEON_PURPLE}Hash türü bilinmiyor!${NC}"
        echo "Sonuç: Bilinmeyen hash türü" >> "$REPORT_FILE"
    fi
}

# Test
# identify_hash "482c811da5d5b4bc6d497ffa98491e38"
# identify_hash "CC03E747A6AFBBCBF8BE7668ACFEBEE5"
# identify_hash "cbfdac6008f9cab4083784cbd1874f76618d2a97"
# identify_hash "$2b$12$KIX5Yk3I0YV6bCQyHzYkZeHZ6gZrtzU7UyVxgNckCVYqM8Pzv0G1u"
# Hash kırma (Güncellenmiş)
crack_hash() {
    local hash=$1
    local wordlist=$2
    local hash_type=$3
    hash_type=$(echo "$hash_type" | tr '[:upper:]' '[:lower:]') # Case-insensitive
    echo -e "${NEON_CYAN}Hash kırma başlıyor... Tür: $hash_type${NC}"
    echo "Hash kırma denemesi: $hash ($hash_type)" >> "$REPORT_FILE"

    if [[ ! -s "$wordlist" ]]; then
        echo -e "${NEON_PURPLE}Hata: Kelime listesi boş veya bulunamadı!${NC}"
        echo "Hata: Kelime listesi boş veya bulunamadı" >> "$REPORT_FILE"
        return 1
    fi

    # Desteklenen hash tipleri
    SUPPORTED_HASHES=("md5" "ntlm" "sha1" "sha224" "sha256" "sha384" "sha512" "bcrypt")
    if [[ ! " ${SUPPORTED_HASHES[@]} " =~ " ${hash_type} " ]]; then
        echo -e "${NEON_PURPLE}Hata: Desteklenmeyen hash türü: $hash_type (${SUPPORTED_HASHES[*]} desteklenir)${NC}"
        echo "Hata: Desteklenmeyen hash türü: $hash_type" >> "$REPORT_FILE"
        return 1
    fi

    # Hashcat önerisi
    if command -v hashcat >/dev/null 2>&1; then
        echo -e "${NEON_CYAN}Hashcat bulundu! Daha hızlı kırma için kullanılabilir.${NC}"
        case $hash_type in
            "md5") hashcat_mode=0 ;;
            "sha1") hashcat_mode=100 ;;
            "sha224") hashcat_mode=611 ;;
            "sha256") hashcat_mode=1400 ;;
            "sha384") hashcat_mode=10800 ;;
            "sha512") hashcat_mode=1700 ;;
            "bcrypt") hashcat_mode=3200 ;;
            "ntlm") hashcat_mode=1000 ;;
        esac
        echo -e "${NEON_CYAN}Hashcat komutu: hashcat -m $hashcat_mode -a 0 '$hash' '$wordlist'${NC}"
        echo "Hashcat önerisi: hashcat -m $hashcat_mode -a 0 '$hash' '$wordlist'" >> "$REPORT_FILE"
    fi

    # Yerel kırma (MD5, SHA1, SHA224, SHA256, SHA384, SHA512)
    if [[ "$hash_type" != "bcrypt" && "$hash_type" != "ntlm" ]]; then
        while IFS= read -r password; do
            case "$hash_type" in
                "md5") computed=$(echo -n "$password" | md5sum | awk '{print $1}') ;;
                "sha1") computed=$(echo -n "$password" | sha1sum | awk '{print $1}') ;;
                "sha224") computed=$(echo -n "$password" | sha224sum | awk '{print $1}') ;;
                "sha256") computed=$(echo -n "$password" | sha256sum | awk '{print $1}') ;;
                "sha384") computed=$(echo -n "$password" | sha384sum | awk '{print $1}') ;;
                "sha512") computed=$(echo -n "$password" | sha512sum | awk '{print $1}') ;;
            esac
            if [[ "$computed" == "$hash" ]]; then
                echo -e "${NEON_GREEN}Hash kırıldı! Şifre: $password${NC}"
                echo "Başarı: Hash kırıldı, şifre: $password" >> "$REPORT_FILE"
                return 0
            fi
            echo -e "${NEON_CYAN}Deneniyor: $password${NC}"
        done < "$wordlist"
        echo -e "${NEON_PURPLE}Hash kırılamadı!${NC}"
        echo "Başarısızlık: Hash kırılamadı" >> "$REPORT_FILE"
        return 1
    else
        # bcrypt ve NTLM için hashcat veya john öner
        if [[ "$hash_type" == "bcrypt" ]]; then
            echo -e "${NEON_PURPLE}Not: bcrypt kırmak için hashcat veya John önerilir.${NC}"
        else
            echo -e "${NEON_PURPLE}Not: NTLM kırmak için hashcat veya John önerilir.${NC}"
        fi
        return 0
    fi
}
# Dosya brute force fonksiyonu
try_password() {
    local password=$1
    local file=$2
    local file_type=$3
    if [ "$file_type" == "zip" ]; then
        unzip -P "$password" -t "$file" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${NEON_GREEN}Şifre bulundu: $password${NC}"
            echo "Başarı: $file için şifre bulundu: $password" >> "$REPORT_FILE"
            return 0
        fi
    elif [ "$file_type" == "rar" ]; then
        unrar t -P"$password" "$file" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${NEON_GREEN}Şifre bulundu: $password${NC}"
            echo "Başarı: $file için şifre bulundu: $password" >> "$REPORT_FILE"
            return 0
        fi
    elif [ "$file_type" == "pdf" ]; then
        pdftk "$file" input_pw "$password" output /dev/null >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${NEON_GREEN}Şifre bulundu: $password${NC}"
            echo "Başarı: $file için şifre bulundu: $password" >> "$REPORT_FILE"
            return 0
        fi
    elif [ "$file_type" == "7z" ]; then
        7z t -p"$password" "$file" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${NEON_GREEN}Şifre bulundu: $password${NC}"
            echo "Başarı: $file için şifre bulundu: $password" >> "$REPORT_FILE"
            return 0
        fi
    fi
    return 1
}

# Menü
show_menu() {
    clear
    echo -e "${NEON_PURPLE}┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳${NC}"
    echo -e "${NEON_PURPLE}┃                 Ulyon Cyber Team: Murat            ┃${NC}"
    echo -e "${NEON_PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻${NC}"
    echo -e "${NEON_CYAN}Seçenekler:${NC}"
    echo -e "${NEON_GREEN}1. ZIP dosyasını brute force ile kır${NC}"
    echo -e "${NEON_GREEN}2. RAR dosyasını brute force ile kır${NC}"
    echo -e "${NEON_GREEN}3. PDF dosyasını brute force ile kır${NC}"
    echo -e "${NEON_GREEN}4. 7z dosyasını brute force ile kır${NC}"
    echo -e "${NEON_GREEN}5. Hash tanımlayıcı (Hash Identifier)${NC}"
    echo -e "${NEON_GREEN}6. Hash kırma (MD5/NTLM/SHA1/SHA224/SHA256/SHA384/SHA512/bcrypt)${NC}"
    echo -e "${NEON_GREEN}7. Çıkış${NC}"
    echo -e "${NEON_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -n -e "${NEON_CYAN}Seçiminizi yapın (1-7): ${NC}"
}

# Ana program
check_tools
# check_tools çağrısından sonra ve while döngüsünden önce yapıştır
cleanup() {
    # rapor dosyası tanımlı mı kontrol et
    if [[ -n "${REPORT_FILE:-}" ]]; then
        echo "Program sonlandırıldı: $(date)" >> "$REPORT_FILE"
    fi

    # geçici dosya varsa temizle (isteğe bağlı, TMP değişkenini kullanıyorsan)
    if [[ -n "${TMP:-}" && -e "$TMP" ]]; then
        rm -f "$TMP"
    fi

    # dosya sistemine flush
    sync

    echo -e "${NEON_PURPLE}Kapatılıyor... Rapor: ${REPORT_FILE:-(yok)}${NC}"
    exit 1
}

# CTRL-C, TERM ve normal çıkış için trap (hepsini yakalar)
trap 'cleanup' INT TERM EXIT
while true; do
    show_menu
    read choice
    case $choice in
        1|2|3|4)
            if [ $choice -eq 1 ]; then
                file_type="zip"
                echo -e "${NEON_CYAN}ZIP dosya yolunu girin:${NC}"
            elif [ $choice -eq 2 ]; then
                file_type="rar"
                echo -e "${NEON_CYAN}RAR dosya yolunu girin:${NC}"
            elif [ $choice -eq 3 ]; then
                file_type="pdf"
                echo -e "${NEON_CYAN}PDF dosya yolunu girin:${NC}"
            else
                file_type="7z"
                echo -e "${NEON_CYAN}7z dosya yolunu girin:${NC}"
            fi
            read target_file
            if [ ! -f "$target_file" ]; then
                echo -e "${NEON_PURPLE}Hata: Dosya bulunamadı!${NC}"
                echo "Hata: $target_file bulunamadı" >> "$REPORT_FILE"
                read -p "Devam etmek için bir tuşa basın..."
                continue
            fi
            echo -e "${NEON_CYAN}Kelime listesi yolunu girin:${NC}"
            read wordlist
            if [ ! -f "$wordlist" ]; then
                echo -e "${NEON_PURPLE}Hata: Kelime listesi bulunamadı!${NC}"
                echo "Hata: $wordlist bulunamadı" >> "$REPORT_FILE"
                read -p "Devam etmek için bir tuşa basın..."
                continue
            fi
            echo -e "${NEON_GREEN}Brute force başlıyor... Hedef: $target_file${NC}"
            echo "Brute force başlatıldı: $target_file ($file_type)" >> "$REPORT_FILE"
            start_time=$(date +%s)
            while IFS= read -r password; do
                echo -e "${NEON_CYAN}Deneniyor: $password${NC}"
                try_password "$password" "$target_file" "$file_type"
                if [ $? -eq 0 ]; then
                    end_time=$(date +%s)
                    echo "Süre: $((end_time - start_time)) saniye" >> "$REPORT_FILE"
                    break
                fi
            done < "$wordlist"
            if [ $? -ne 0 ]; then
                echo -e "${NEON_PURPLE}Şifre bulunamadı!${NC}"
                echo "Başarısızlık: $target_file için şifre bulunamadı" >> "$REPORT_FILE"
                end_time=$(date +%s)
                echo "Süre: $((end_time - start_time)) saniye" >> "$REPORT_FILE"
            fi
            read -p "Devam etmek için bir tuşa basın..."
            ;;
        5)
            echo -e "${NEON_CYAN}Analiz etmek için hash değerini girin:${NC}"
            read hash
            identify_hash "$hash"
            read -p "Devam etmek için bir tuşa basın..."
            ;;
        6)
            echo -e "${NEON_CYAN}Hash değerini girin:${NC}"
            read hash
            echo -e "${NEON_CYAN}Hash türü (md5/sha1):${NC}"
            read hash_type
            if [[ "$hash_type" != "md5" && "$hash_type" != "sha1" ]]; then
                echo -e "${NEON_PURPLE}Hata: Sadece md5 veya sha1 desteklenir!${NC}"
                echo "Hata: Geçersiz hash türü: $hash_type" >> "$REPORT_FILE"
                read -p "Devam etmek için bir tuşa basın..."
                continue
            fi
            echo -e "${NEON_CYAN}Kelime listesi yolunu girin:${NC}"
            read wordlist
            if [ ! -f "$wordlist" ]; then
                echo -e "${NEON_PURPLE}Hata: Kelime listesi bulunamadı!${NC}"
                echo "Hata: $wordlist bulunamadı" >> "$REPORT_FILE"
                read -p "Devam etmek için bir tuşa basın..."
                continue
            fi
            start_time=$(date +%s)
            crack_hash "$hash" "$wordlist" "$hash_type"
            end_time=$(date +%s)
            echo "Süre: $((end_time - start_time)) saniye" >> "$REPORT_FILE"
            read -p "Devam etmek için bir tuşa basın..."
            ;;
        7)
            echo -e "${NEON_GREEN}CyberBrute v2 kapatılıyor. Rapor: $REPORT_FILE${NC}"
            echo "Program kapatıldı: $(date)" >> "$REPORT_FILE"
            exit 0
            ;;
        *)
            echo -e "${NEON_PURPLE}Geçersiz seçim! Lütfen 1-7 arasında bir sayı girin.${NC}"
            read -p "Devam etmek için bir tuşa basın..."
            ;;
    esac
done
