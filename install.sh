#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
fail() { printf '[x] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

pkg_manager() {
    if have apt-get; then echo apt
    elif have dnf; then echo dnf
    elif have pacman; then echo pacman
    elif have brew; then echo brew
    else echo none
    fi
}

install_go() {
    info "installing Go via $(pkg_manager)"
    case "$(pkg_manager)" in
        apt)    sudo apt-get update && sudo apt-get install -y golang-go ;;
        dnf)    sudo dnf install -y golang ;;
        pacman) sudo pacman -S --noconfirm go ;;
        brew)   brew install go ;;
        none)   fail "no supported package manager found. Install Go >= 1.21 from https://go.dev/dl then re-run this script" ;;
    esac
}

go_bin_dir() {
    local dir
    dir="$(go env GOBIN 2>/dev/null || true)"
    if [ -z "$dir" ]; then
        dir="$(go env GOPATH 2>/dev/null || printf '%s/go' "$HOME")/bin"
    fi
    printf '%s' "$dir"
}

ensure_go_path() {
    local bin="$1"
    case ":${PATH}:" in
        *":${bin}:"*) return 0 ;;
    esac
    warn "${bin} is not on PATH — adding it to shell rc files"
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
        if [ -f "$rc" ] && ! grep -qF "$bin" "$rc"; then
            printf '\nexport PATH="$PATH:%s"\n' "$bin" >> "$rc"
            info "added PATH export to ${rc}"
        fi
    done
    export PATH="${PATH}:${bin}"
}

install_pd_tools() {
    info "installing subfinder, httpx, naabu, dnsx, tlsx, katana, nuclei (go install)"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    info "installing gau, ffuf, dalfox (go install)"
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/ffuf/ffuf/v2@latest
    go install -v github.com/hahwul/dalfox/v2@latest
}

install_nmap() {
    if have nmap; then
        info "nmap already installed"
        return
    fi
    info "installing nmap"
    case "$(pkg_manager)" in
        apt)    sudo apt-get install -y nmap ;;
        dnf)    sudo dnf install -y nmap ;;
        pacman) sudo pacman -S --noconfirm nmap ;;
        brew)   brew install nmap ;;
        none)   warn "could not install nmap automatically" ;;
    esac
}

install_cli() {
    info "installing reconn CLI"
    if ! have pipx; then
        case "$(pkg_manager)" in
            apt)    sudo apt-get install -y pipx ;;
            dnf)    sudo dnf install -y pipx ;;
            pacman) sudo pacman -S --noconfirm python-pipx ;;
            brew)   brew install pipx ;;
            none)   warn "no pipx — install it or run: pip install -e ${SCRIPT_DIR}"; return ;;
        esac
    fi
    pipx install --force "$SCRIPT_DIR" || warn "pipx install failed — run manually: pipx install ${SCRIPT_DIR}"
    if have reconn; then
        info "reconn -> $(command -v reconn)"
    else
        warn "reconn installed but not on PATH — run: pipx ensurepath"
    fi
}

install_whois() {
    if have whois; then
        info "whois already installed"
        return
    fi
    info "installing whois"
    case "$(pkg_manager)" in
        apt)    sudo apt-get install -y whois ;;
        dnf)    sudo dnf install -y whois ;;
        pacman) sudo pacman -S --noconfirm whois ;;
        brew)   brew install whois ;;
        none)   warn "could not install whois automatically" ;;
    esac
}

install_dnsrecon() {
    if have dnsrecon; then
        info "dnsrecon already installed"
        return
    fi
    info "installing dnsrecon"
    if have pipx && pipx install dnsrecon; then
        return
    fi
    if [ "$(pkg_manager)" = "apt" ] && sudo apt-get install -y dnsrecon; then
        return
    fi
    if have pip3 && pip3 install --user dnsrecon; then
        return
    fi
    warn "dnsrecon could not be installed automatically — run: pip install dnsrecon"
}

verify() {
    local missing=0 tool
    for tool in subfinder httpx naabu dnsrecon dnsx tlsx katana gau nuclei whois ffuf dalfox nmap; do
        if have "$tool"; then
            info "$tool -> $(command -v "$tool")"
        else
            warn "$tool NOT FOUND"
            missing=1
        fi
    done
    return "$missing"
}

main() {
    if ! have go; then
        install_go
    fi
    have go || fail "Go is still not available"

    ensure_go_path "$(go_bin_dir)"
    install_pd_tools
    install_dnsrecon
    install_whois
    install_nmap
    install_cli

    echo
    if verify; then
        info "done — run: reconn -d example.com"
    else
        warn "setup finished with missing tools — see warnings above"
        exit 1
    fi
}

main "$@"
