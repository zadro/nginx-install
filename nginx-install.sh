#!/bin/bash
# ====================================================================
# Nginx Installation Script
# ====================================================================
# Author: Dario Zadro
# License: GNU General Public License v3.0
# Website: https://zadroweb.com
# ====================================================================
# This script installs Nginx from source with optional modules and 
# configures automatic GeoIP database updates via cron.
#
# This project was inspired by https://github.com/angristan/nginx-autoinstall
#
# USE AT YOUR OWN RISK. This script is provided "as is," without any
# warranties or guarantees. Always review before running in production.
# ====================================================================
if [[ "$EUID" -ne 0 ]]; then
    echo -e "Sorry, you need to run this as root"
    exit 1
fi

# Define versions
NGINX_MAINLINE_VER=1.27.4
NGINX_STABLE_VER=1.26.3         # http://nginx.org/en/download.html
OPENSSL_VER=3.4.1               # https://www.openssl.org/source/
LIBMAXMINDDB_VER=1.10.0         # https://github.com/maxmind/libmaxminddb/releases
GEOIP2_VER=3.4                  # https://github.com/leev/ngx_http_geoip2_module/releases
MAXMINDKEY=""                   # Get key from maxmind.com
MAXMINDID=""                    # Get ID from maxmind.com

# clear screen before starting
clear
echo ""
echo "Welcome to the Nginx install script."
echo ""
echo "What would you like to do?"
echo "   1) Install or update Nginx"
echo "   2) Uninstall Nginx"
echo "   3) Exit"
echo ""
while [[ $OPTION !=  "1" && $OPTION != "2" && $OPTION != "3" ]]; do
    read -p "Select an option [1-3]: " OPTION
done

case $OPTION in
    1)
        echo ""
        echo "This script will install Nginx with some optional modules."
        echo ""
        echo "Do you prefer Nginx stable or mainline?"
        echo "   1) Stable $NGINX_STABLE_VER"
        echo "   2) Mainline $NGINX_MAINLINE_VER"
        echo ""
        while [[ $NGINX_VER != "1" && $NGINX_VER != "2" ]]; do
            read -p "Select an option [1-2]: " NGINX_VER
        done
        case $NGINX_VER in
            1)
            NGINX_VER=$NGINX_STABLE_VER
            ;;
            2)
            NGINX_VER=$NGINX_MAINLINE_VER
            ;;
            *)
            echo "NGINX_VER unspecified, fallback to stable $NGINX_STABLE_VER"
            NGINX_VER=$NGINX_STABLE_VER
            ;;
        esac
        echo ""
        echo "Choose your modules..."
        echo ""
        echo "Modules to install:"
        while [[ $BROTLI != "y" && $BROTLI != "n" ]]; do
            read -p "       Brotli [y/n]: " -e BROTLI
        done
        while [[ $GEOIP != "y" && $GEOIP != "n" ]]; do
            read -p "       GeoIP (requires maxmind.com account) [y/n]: " -e GEOIP
        done
        if [[ "$GEOIP" = 'y' ]]; then
            read -p "       MaxMind Account ID (leave blank to skip GeoIP): " -e MAXMINDID
            if [[ ! -z "$MAXMINDID" ]]; then
                read -p "       MaxMind License Key: " -e MAXMINDKEY
                if [[ -z "$MAXMINDKEY" ]]; then
                    echo "No MaxMind License Key provided. GeoIP will be skipped."
                    GEOIP="n"
                fi
            else
                echo "No MaxMind Account ID provided. GeoIP will be skipped."
                GEOIP="n"
            fi
        fi        
        while [[ $VTS != "y" && $VTS != "n" ]]; do
            read -p "       Virtual Traffic Status (might cause high CPU load) [y/n]: " -e VTS
        done
        while [[ $MODSEC != "y" && $MODSEC != "n" ]]; do
            read -p "       ModSecurity [y/n]: " -e MODSEC
        done
        while [[ $CERTBOT != "y" && $CERTBOT != "n" ]]; do
            read -p "       Let's Encrypt Certbot [y/n]: " -e CERTBOT
        done        
        echo ""
        echo "Choose your OpenSSL preference:"
        echo "   1) System's OpenSSL ($(openssl version | cut -c9-14))"
        echo "   2) OpenSSL $OPENSSL_VER from source"
        echo ""
        while [[ $SSL != "1" && $SSL != "2" ]]; do
            read -p "Select an option [1-2]: " SSL
        done
        case $SSL in
            1)
            ;;
            2)
                OPENSSL=y
            ;;
            *)
                echo "SSL unspecified, fallback to system's OpenSSL ($(openssl version | cut -c9-14))"
            ;;
        esac
        echo ""
        read -n1 -r -p "Nginx is ready to be installed, press any key to continue..."
        echo ""

        # Cleanup
        # The directory should be deleted at the end of the script, but in case it fails
        rm -r /usr/local/src/nginx/ >> /dev/null 2>&1
        mkdir -p /usr/local/src/nginx/modules

        # Install essential build dependencies
        apt-get update
        apt-get install -y build-essential ca-certificates wget curl \
            libpcre3 libpcre3-dev libssl-dev zlib1g-dev \
            autoconf automake libtool git cmake || {
                echo "Error installing dependencies"
                exit 1
            }

        # Install certbot if selected
        if [[ "$CERTBOT" = 'y' ]]; then
        # Prevent nginx start errors!
        systemctl mask nginx
            apt-get install -y python3-certbot-nginx || {
                echo "Error installing certbot"
                exit 1
            }
            echo "Certbot must be installed before nginx."
            echo "You can now use 'certbot --nginx' to obtain and configure SSL certificates."
        fi

        #Modsec dependencies
        if [[ "$MODSEC" = 'y' ]]; then
            apt-get install -y libcurl4-openssl-dev liblmdb-dev libyajl-dev pkgconf libxml2-dev libxslt1-dev || {
                echo "Error installing dependencies"
                exit 1
            }
        fi

        #Brotli
        if [[ "$BROTLI" = 'y' ]]; then
            apt-get install -y libbrotli-dev || {
                echo "Error installing dependencies"
                exit 1
            }

            cd /usr/local/src/nginx/modules || exit 1
            git clone https://github.com/google/ngx_brotli
            cd ngx_brotli/deps/brotli || exit 1
            git submodule update --init --recursive
        fi

        # GeoIP
        # SEE maxmind.com to obtain key
        # GeoIP
        if [[ "$GEOIP" == 'y' ]]; then
            if grep -q "main contrib" /etc/apt/sources.list; then
                    echo "main contrib already in sources.list... Skipping"
            else
                    sed -i "s/main/main contrib/g" /etc/apt/sources.list
            fi
            apt-get update
            apt-get install -y geoipupdate

            cd /usr/local/src/nginx/modules || exit 1
            # install libmaxminddb
            wget https://github.com/maxmind/libmaxminddb/releases/download/${LIBMAXMINDDB_VER}/libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
            tar xaf libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
            cd libmaxminddb-${LIBMAXMINDDB_VER}/ || exit 1
            ./configure
            make -j "$(nproc)"
            make install
            ldconfig

            cd ../ || exit 1
            wget https://github.com/leev/ngx_http_geoip2_module/archive/${GEOIP2_VER}.tar.gz
            tar xaf ${GEOIP2_VER}.tar.gz

            mkdir geoip-db
            cd geoip-db || exit 1
            # - Download GeoLite2 databases using license key
            # - Apply the correct, dated filename inside the checksum file to each download instead of a generic filename
            # - Perform all checksums
            GEOIP2_URLS=( \
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key="$MAXMINDKEY"&suffix=tar.gz" \
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key="$MAXMINDKEY"&suffix=tar.gz" \
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key="$MAXMINDKEY"&suffix=tar.gz" \
            )
            if [[ ! -d /opt/geoip ]]; then
                for GEOIP2_URL in "${GEOIP2_URLS[@]}"; do
                    echo "=== FETCHING ==="
                    echo $GEOIP2_URL
                    wget -O sha256 "$GEOIP2_URL.sha256"
                    GEOIP2_FILENAME=$(cat sha256 | awk '{print $2}')
                    mv sha256 "$GEOIP2_FILENAME.sha256"
                    wget -O "$GEOIP2_FILENAME" "$GEOIP2_URL"
                    echo "=== CHECKSUM ==="
                    sha256sum -c "$GEOIP2_FILENAME.sha256"
                done
                tar -xf GeoLite2-ASN_*.tar.gz
                tar -xf GeoLite2-City_*.tar.gz
                tar -xf GeoLite2-Country_*.tar.gz
                mkdir /opt/geoip
                cd GeoLite2-ASN_*/ || exit 1
                mv GeoLite2-ASN.mmdb /opt/geoip/
                cd ../ || exit 1
                cd GeoLite2-City_*/ || exit 1
                mv GeoLite2-City.mmdb /opt/geoip/
                cd ../ || exit 1
                cd GeoLite2-Country_*/ || exit 1
                mv GeoLite2-Country.mmdb /opt/geoip/
            else
                echo -e "GeoLite2 database files exists... Skipping download"
            fi
            # Download GeoIP.conf for use with geoipupdate
            if [[ ! -f /usr/local/etc/GeoIP.conf ]]; then
                cd /usr/local/etc || exit 1
                wget https://raw.githubusercontent.com/zadro/nginx-install/refs/heads/main/GeoIP.conf
                sed -i "s/YOUR_ACCOUNT_ID_HERE/${MAXMINDID}/g" GeoIP.conf
                sed -i "s/YOUR_LICENSE_KEY_HERE/${MAXMINDKEY}/g" GeoIP.conf
            else
                echo -e "GeoIP.conf file exists... Skipping"
            fi
            # Always create or overwrite /etc/cron.d/geoipupdate with the correct cron job for /usr/local
            echo -e "47 6 * * 3 root test -x /usr/bin/geoipupdate && (grep -q '^AccountID .*[^0]\+' /etc/GeoIP.conf || grep -q '^AccountID .*[^0]\+' /usr/local/etc/GeoIP.conf) && test ! -d /run/systemd/system && /usr/bin/geoipupdate" > /etc/cron.d/geoipupdate
            # Ensure correct permissions
            chmod 644 /etc/cron.d/geoipupdate
            echo -e "geoipupdate crontab file has been created/updated successfully."
        fi

        # OpenSSL
        if [[ "$OPENSSL" = 'y' ]]; then
            cd /usr/local/src/nginx/modules || exit 1
            wget https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz
            tar xaf openssl-${OPENSSL_VER}.tar.gz
            cd openssl-${OPENSSL_VER}
            ./config
        fi

        # ModSecurity
        if [[ "$MODSEC" == 'y' ]]; then
            cd /usr/local/src/nginx/modules || exit 1
            git clone --depth 1 -b v3/master --single-branch https://github.com/owasp-modsecurity/ModSecurity
            cd ModSecurity || exit 1
            git submodule init
            git submodule update
            ./build.sh
            ./configure
            make -j "$(nproc)"
            make install

            if [[ ! -d /etc/nginx/modsec ]]; then
            mkdir /etc/nginx/modsec
                wget -P /etc/nginx/modsec/ https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/modsecurity.conf-recommended
                wget -P /etc/nginx/modsec/ https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/unicode.mapping
                mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
                sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
            else
                    echo -e "Modsec directory exists... Skipping download"
            fi
        fi

        # Download and extract of Nginx source code
        cd /usr/local/src/nginx/ || exit 1
        wget -qO- http://nginx.org/download/nginx-${NGINX_VER}.tar.gz | tar zxf -
        cd nginx-${NGINX_VER}

        # As the default nginx.conf does not work, we download a clean and working conf from my GitHub.
        # We do it only if it does not already exist, so that it is not overriten if Nginx is being updated
        if [[ ! -e /etc/nginx/nginx.conf ]]; then
            mkdir -p /etc/nginx
            cd /etc/nginx || exit 1
            wget https://raw.githubusercontent.com/zadro/nginx-install/refs/heads/main/nginx.conf
        fi
        cd /usr/local/src/nginx/nginx-${NGINX_VER} || exit 1

        NGINX_MODULES="--with-compat \
        --with-threads \
        --with-file-aio \
        --with-compat \
        --with-http_addition_module \
        --with-http_auth_request_module \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-http_realip_module \
        --with-http_secure_link_module \
        --with-http_slice_module \
        --with-http_sub_module \
        --with-mail \
        --with-mail_ssl_module \
        --with-stream \
        --with-stream_realip_module \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module"

        # Optional modules
        if [[ "$BROTLI" = 'y' ]]; then
            NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_brotli")
        fi

        if [[ "$GEOIP" = 'y' ]]; then
            NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_http_geoip2_module-${GEOIP2_VER}")
        fi

        if [[ "$OPENSSL" = 'y' ]]; then
            NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-openssl=/usr/local/src/nginx/modules/openssl-${OPENSSL_VER}")
        fi

        if [[ "$MODSEC" = 'y' ]]; then
            git clone --depth 1 --quiet https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/nginx/modules/ModSecurity-nginx
            NGINX_MODULES=$(echo "$NGINX_MODULES"; echo --add-module=/usr/local/src/nginx/modules/ModSecurity-nginx)
        fi

        # See https://github.com/vozlt/nginx-module-vts for setup
        if [[ "$VTS" = 'y' ]]; then
            git clone --depth 1 --quiet https://github.com/vozlt/nginx-module-vts.git /usr/local/src/nginx/modules/nginx-module-vts
            NGINX_MODULES=$(echo "$NGINX_MODULES"; echo --add-module=/usr/local/src/nginx/modules/nginx-module-vts)
        fi

        ./configure --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --modules-path=/usr/lib/nginx/modules \
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/var/log/nginx/error.log \
            --http-log-path=/var/log/nginx/access.log \
            --pid-path=/var/run/nginx.pid \
            --lock-path=/var/run/nginx.lock \
            --http-client-body-temp-path=/var/cache/nginx/client_temp \
            --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
            --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
            --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
            --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
            --user=nginx \
            --group=nginx \
            --with-cc-opt=-Wno-deprecated-declarations \
            $NGINX_MODULES

        make -j "$(nproc)"
        make install

        # remove debugging symbols
        strip -s /usr/sbin/nginx

        # Nginx installation from source does not add an init script for systemd and logrotate
        # Using the official systemd script and logrotate conf from nginx.org
        if [[ ! -e /lib/systemd/system/nginx.service ]]; then
            cd /lib/systemd/system/ || exit 1
            wget https://raw.githubusercontent.com/zadro/nginx-install/refs/heads/main/nginx.service
            # Enable nginx start at boot
            systemctl enable nginx
        fi

        if [[ ! -e /etc/logrotate.d/nginx ]]; then
            cd /etc/logrotate.d/ || exit 1
            wget https://raw.githubusercontent.com/zadro/nginx-install/refs/heads/main/nginx -O nginx
        fi

        # Nginx's cache directory is not created by default
        if [[ ! -d /var/cache/nginx ]]; then
            mkdir -p /var/cache/nginx
        fi

        # We add the sites-* folders as some use them.
        if [[ ! -d /etc/nginx/sites-available ]]; then
            mkdir -p /etc/nginx/sites-available
        fi
        if [[ ! -d /etc/nginx/sites-enabled ]]; then
            mkdir -p /etc/nginx/sites-enabled
        fi
        if [[ ! -d /etc/nginx/conf.d ]]; then
            mkdir -p /etc/nginx/conf.d
        fi

        # Restart Nginx
        systemctl unmask nginx
        systemctl restart nginx

        # Block Nginx from being installed via APT
        if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]
        then
            cd /etc/apt/preferences.d/ || exit 1
            echo -e "Package: nginx*\\nPin: release *\\nPin-Priority: -1" > nginx-block
        fi

        # Removing temporary Nginx and modules files
        rm -r /usr/local/src/nginx

        # Done!!
        echo "Installation done."
    exit
    ;;
    2) # Uninstall Nginx
        while [[ $RM_CONF !=  "y" && $RM_CONF != "n" ]]; do
            read -p "       Remove configuration files ? [y/n]: " -e RM_CONF
        done
        while [[ $RM_LOGS !=  "y" && $RM_LOGS != "n" ]]; do
            read -p "       Remove logs files ? [y/n]: " -e RM_LOGS
        done

        # Stop Nginx
        systemctl stop nginx

        # Removing Nginx files and modules files
        rm -r /usr/local/src/nginx \
        /usr/sbin/nginx* \
        /etc/logrotate.d/nginx \
        /var/cache/nginx \
        /lib/systemd/system/nginx.service \
        /etc/systemd/system/multi-user.target.wants/nginx.service

        # Remove conf files
        if [[ "$RM_CONF" = 'y' ]]; then
            rm -r /etc/nginx/
        fi

        # Remove logs
        if [[ "$RM_LOGS" = 'y' ]]; then
            rm -r /var/log/nginx
        fi

        # Remove Nginx APT block
        if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]
        then
            rm /etc/apt/preferences.d/nginx-block
        fi

        # We're done !
        echo "Uninstallation done."

        exit
    ;;
    *) # Exit
        exit
    ;;

esac
