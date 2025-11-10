### 1. Install dependencies
```bash
yum install -y rpm-build
yum install -y make
yum install -y cmake
yum install -y gcc
yum install -y gcc-c++
yum install -y glibc-devel
yum install -y openssl-devel
yum install -y glib2-devel
yum install -y libnl3-devel
yum install -y kernel-devel  # ubcore is necessary from openEuler kernel
```

### 2. Install user mode packages
#### Method 1: Use the make install command to compile and install
```bash
cd src
mkdir build
cd build
cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable
make install -j
```

#### Method 2: Compile the URMA rpm package separately and generate it under the path /root/rpmbuild/RPMS/aarch64
```bash
mkdir -p /root/rpmbuild/SOURCES/
cd /UMDK
tar -czf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git `ls -A`
rpmbuild -ba umdk.spec --with urma
cd /root/rpmbuild/RPMS/aarch64
rpm -Uvh umdk-urma-lib-25.12.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-bin-25.12.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-tools-25.12.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-example-25.12.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-devel-25.12.0-0.aarch64.rpm --force --nodeps
```

#### Method 3: yum install
```bash
yum install -y umdk-urma-lib-25.12.0-0.aarch64
yum install -y umdk-urma-bin-25.12.0-0.aarch64
yum install -y umdk-urma-example-25.12.0-0.aarch64
yum install -y umdk-urma-tools-25.12.0-0.aarch64
yum install -y umdk-urma-devel-25.12.0-0.aarch64
```

### 3. Install dependent kernel state ko
```bash
cd /lib/modules/$(uname -r)/kernel/drivers
insmod ub/ubfi/ubfi.ko.xz  cluster=1 # When using the vf network card, you need to remove the cluster=1 parameter
insmod iommu/ummu-core/ummu-core.ko.xz
insmod ub/hisi-ub/kernelspace/ummu/drivers/ummu.ko.xz
insmod ub/hisi-ub/kernelspace/ubus/ubus.ko.xz cc_en=0  um_entry_size=1
insmod ub/hisi-ub/kernelspace/ubus/vendor/hisi/hisi_ubus.ko.xz msg_wait=2000 fe_msg=1 um_entry_size1=0 cfg_entry_offset=512
insmod ub/hisi-ub/kernelspace/ubase/ubase.ko.xz
insmod ub/hisi-ub/kernelspace/unic/unic.ko.xz tx_timeout_reset_bypass=1
insmod ub/hisi-ub/kernelspace/cdma/cdma.ko.xz
modprobe ubcore uburma
modprobe udma dfx_switch=1 jfc_arm_mode=2 is_active=0 fast_destroy_tp=0
modprobe ubagg
```

### 4. Run the example
```bash
systemctl start scbus-daemon.service
urma_admin show
run server: urma_perftest send_bw -d bonding_dev_0 -s 2 -n 10 -I 128 -p 1
run client: urma_perftest send_bw -d bonding_dev_0 -s 2 -n 10 -I 128 -p 1 -S <server_ip>
```

