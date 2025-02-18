# nginx-install

A bare-bones Bash script to install **Nginx from source** with optional modules and **GeoIP database updates via cron**.

## Installation

Run the following commands to download and execute the script:

```bash
wget https://raw.githubusercontent.com/zadro/nginx-install/refs/heads/main/nginx-install.sh
chmod +x nginx-install.sh
./nginx-install.sh
```

## Features
- Installs **Nginx from source** with optional modules.
- Supports **Brotli, ModSecurity, GeoIP2, and other modules**.
- Configures **automatic GeoIP database updates** via cron.
- Ensures a **clean, optimized, and lightweight build**.
- Simple and uncomplicated nginx install script.
- Includes HTTP/3 module. 

## Disclaimer
This script is provided **"as is"**, without any warranties or guarantees.  
Always review the script before running it on a production server.

## Credits
- Inspired by **[angristan/nginx-autoinstall](https://github.com/angristan/nginx-autoinstall)**.
- Developed by **Dario Zadro** - [zadroweb.com](https://zadroweb.com).

## License
Licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.
