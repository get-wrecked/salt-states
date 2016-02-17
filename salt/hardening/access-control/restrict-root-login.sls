# Ref. NSA RHEL 2.3.1.1

# TODO: There were some lines in securetty related to LXC containers,
# figure out if this impacts containers in any way

hardening-access-control-restrict-root-login:
    file.managed:
        - name: /etc/securetty
        - contents: |
            console
            tty1
            tty2
            tty3
            tty4
            tty5
            tty6
            tty7
            tty8
            tty9
            tty10
            tty11
            tty12
            tty13
            tty14
            tty15
            tty16
            tty17
            tty18
            tty19
            tty20
            tty21
            tty22
            tty23
            tty24
            tty25
            tty26
            tty27
            tty28
            tty29
            tty30
            tty31
            tty32
            tty33
            tty34
            tty35
            tty36
            tty37
            tty38
            tty39
            tty40
            tty41
            tty42
            tty43
            tty44
            tty45
            tty46
            tty47
            tty48
            tty49
            tty50
            tty51
            tty52
            tty53
            tty54
            tty55
            tty56
            tty57
            tty58
            tty59
            tty60
            tty61
            tty62
            tty63
