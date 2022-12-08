### Qubes Keepass

----

*qubes-keepass* is a [rofi](https://github.com/davatorium/rofi) based frontend for [KeePassXC](https://keepassxc.org/)
which integrates nicely with the isolation and security features of [Qubes OS](https://www.qubes-os.org/). It enables you
to easily copy credentials to currently focused Qube, to define allow lists for credentials based on Qube names and to
automatically clear the Qubes clipboard after a configurable amount of time.

*qubes-keepass* is inspired by [rofi-pass](https://github.com/carnager/rofi-pass) which provides a rofi based frontend
for the password manager [pass](https://www.passwordstore.org/).


### Installation

----

*qubes-keepass* relies on *Qubes qrexec* mechanism and requires multiple installation steps in different Qubes. In the
following, it is assumed that your *KeePassXC* database is contained within a Qube named `vault`, that your window manager
is [i3](https://www.qubes-os.org/doc/i3/) and that you have an *AppVM Qube* called `app-vm`.


#### dom0

In `dom0` create a policy file for the [custom.QubesKeepass](/etc/qubes-rpc/policy/custom.QubesKeepass) *qrexec* service.
This service will be invoked by your `vault` Qube to copy credentials to other *AppVMs*:

```console
[user@dom0 ~]$ cat /etc/qubes-rpc/policy/custom.QubesKeepass
vault $anyvm allow
```

According to your preferences, you could also choose `ask` instead of the `allow` action. Now copy the
[qubes-keepass-dom0.sh](./qubes-keepass-dom0.sh) script to an location within your `$PATH` environment variable
and make sure that it is executable.

Finally, set up a shortcut for invoking `qubes-keepass-dom0.sh` in your *i3* configuration file and make sure that
the window class `Rofi` is configured to floating:

```console
[user@dom0 ~]$ cat /.config/i3/config
...
bindsym $mod+p exec --no-startup-id qubes-keepass-dom0.sh
for_window [class="Rofi"] floating enable
```


#### vault

In your `vault` VM you need to enable the *Secret Service* integration for *KeePassXC*. This can be configured within
the database settings and requires that no other *Secret Service Providers* is running. By default, you probably have
`gnome-keyring-daemon` as *Secret Service Provider* running in your `vault` VM. The recommended way to disable it is
by modifying it's autostart entry. First, setup a [binddir](https://www.qubes-os.org/doc/bind-dirs/) for your `vault` VM:

```console
[user@vault ~]$ cat rw/config/qubes-bind-dirs.d/50_user.conf
binds+=( '/etc/xdg/autostart/gnome-keyring-secrets.desktop' )
```

Now restart the `vault` VM and add `Hidden=true` to the `/etc/xdg/autostart/gnome-keyring-secrets.desktop` file:

```console
[user@vault ~]$ cat /etc/xdg/autostart/gnome-keyring-secrets.desktop
...
Hidden=true
```

After restarting the `vault` VM again, the `gnome-keyring-daemon` should no longer start up and you can enable the *Secret
Service* integration in the *KeePassXC* database settings.

Additionally, you need to expose the credentials you want to use with *qubes-keepass* to the *Secret Service* within your
database security settings. If you simply want to use your complete database with *qubes-keepass*, just select the your
*Root* folder.

Finally, copy the [qubes-keepass.py](./qubes-keepass.py) script to your `vault` VM and make sure it is executable. Also make
sure that the location specified in [qubes-keepass-dom0.sh](./qubes-keepass-dom0.sh) matches the location you copied the script
to (default is `/home/user/.local/bin/qubes-keepass.py`).


#### app-vm

For each *AppVM* that is allowed to obtain credentials from *qubes-keepass*, you need to setup an *qrexec* service. This service
is essentially just a pipe to `xclip` and looks like this:

```console
[user@app-vm ~]$ cat etc/qubes-rpc/custom.QubesKeepass
#!/usr/bin/sh

# Do not remove the redirect, as xclip will block the qrexec call without it.
xclip -selection clipboard &> /dev/null
```

Make sure that is executable and that such a file exists on each *AppVM* you want to use *qubes-keepass* with.


### Usage

----

After pressing the configured shortcut for `qubes-keepass-dom0.sh`, *qubes-keepass* determines your currently focused Qube
and displays available credentials from your *KeePassXC* database in *rofi*. After you selected a credential, it is copied
to previously determined focused Qube using the `custom.QubesKeepass` *qrexec* service.

Within *rofi* you can press the following keys to copy different attributes of the credential:

* `Return` or `Ctrl+c`: Copy password
* `Ctrl+C`: Copy username
* `Ctrl+Shift+u`: Copy URL


### Configuration

----

*qubes-keepass* is mainly configured directly inside the `qubes-keepass.py` script. In the beginning of the script, you can find
some global variables that can be adjusted to your preferences. This includes the *rofi* keybindings, the default timeout when
credentials get cleared and a list of restricted Qubes (this is explained next).

Moreover, *qubes-keepass* also supports some credential specific configurations, that can be applied within the *Notes* section
of a *KeePassXC* credential. The following listing shows an example for such a configuration:

```ini
[QubesKeepass]
qubes = work, personal
timeout = 5
```

The `timeout` key specifies a credential specific timeout for the credential. The `qubes` key specifies an allow list of qubes for
the credential. In the example above, the credential will only be listed when you are currently copying into the `work` or `personal`
Qube. When copying in other Qubes, the credential is not shown and not allowed to be copied.

You can also restrict a Qube to only use credentials that are explicitly defined for this Qube. Just add the desired Qubes to the
`restricted` variable within `qubes-keepass.py`. When copying to these Qubes, only credentials are displayed that have the corresponding
Qube name explicitly configured in their `QubesKeepass` section.


### FAQ

----

**Q**: Isn't exposing credentials via DBus insecure?
**A**: No. Despite Keepass attempts to protect your credentials in memory, you should assume that each process running on the same machine
as your Keepass instance is able to access these credentials by dumping them from memory. DBus access makes the process of dumping credentials
more comfortable, but it is not a requirement. Moreover, your `vault` VM is considered trusted and other VMs are not able to access your secrets.
If you are really concerned about the DBus access, you can configure Keepass to display a prompt for each credential access via DBus.

**Q**: Should I configure `custom.QubesKeepass` using the `ask` or `allow` policy?
**A**: It depends. `custom.QubesKeepass` adds a communication channel from your `vault` VM to other VMs. This communication channel is only unidirectional,
but it could still allow to exfiltrate data from your `vault` into an *online* VM. That being said, the same is true for other Qubes mechanisms like
[split-SSH](https://github.com/Qubes-Community/Contents/blob/master/docs/configuration/split-ssh.md). If having a malicious process in your `vault` VM that
exfiltrates data using your clipboard is something you worry about. you should use `ask`. If you like things more comfortable, you should use `allow` instead.
When using `allow` you can also add a notifier command to the *qrexec* service, to be at least informed, when something gets copied.
