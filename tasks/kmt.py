import json
import os
import platform
import tempfile
from dataclasses import dataclass
from glob import glob
from pathlib import Path

from invoke import task

from .kernel_matrix_testing import stacks, vmconfig
from .kernel_matrix_testing.command import CommandRunner
from .kernel_matrix_testing.compiler import build_compiler as build_cc
from .kernel_matrix_testing.compiler import compiler_running, docker_exec
from .kernel_matrix_testing.compiler import start_compiler as start_cc
from .kernel_matrix_testing.download import arch_mapping, update_rootfs
from .kernel_matrix_testing.init_kmt import check_and_get_stack, init_kernel_matrix_testing_system
from .kernel_matrix_testing.kmt_os import get_kmt_os
from .kernel_matrix_testing.tool import Exit, ask, info, warn
from .system_probe import EMBEDDED_SHARE_DIR

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

X86_AMI_ID_SANDBOX = "ami-0d1f81cfdbd5b0188"
ARM_AMI_ID_SANDBOX = "ami-02cb18e91afb3777c"


@task
def create_stack(ctx, stack=None):
    stacks.create_stack(ctx, stack)


@task(
    help={
        "vms": "Comma separated List of VMs to setup. Each definition must contain the following elemets (recipe, architecture, version).",
        "stack": "Name of the stack within which to generate the configuration file",
        "vcpu": "Comma separated list of CPUs, to launch each VM with",
        "memory": "Comma separated list of memory to launch each VM with. Automatically rounded up to power of 2",
        "new": "Generate new configuration file instead of appending to existing one within the provided stack",
        "init-stack": "Automatically initialize stack if not present. Equivalent to calling 'inv -e kmt.create-stack [--stack=<stack>]'",
    }
)
def gen_config(
    ctx,
    stack=None,
    vms="",
    sets="",
    init_stack=False,
    vcpu="4",
    memory="8192",
    new=False,
    ci=False,
    arch="",
    output_file="vmconfig.json",
):
    vmconfig.gen_config(ctx, stack, vms, sets, init_stack, vcpu, memory, new, ci, arch, output_file)


@task
def launch_stack(ctx, stack=None, ssh_key="", x86_ami=X86_AMI_ID_SANDBOX, arm_ami=ARM_AMI_ID_SANDBOX):
    stacks.launch_stack(ctx, stack, ssh_key, x86_ami, arm_ami)


@task
def destroy_stack(ctx, stack=None, pulumi=False, ssh_key=""):
    clean(ctx, stack)
    stacks.destroy_stack(ctx, stack, pulumi, ssh_key)


@task
def pause_stack(_, stack=None):
    stacks.pause_stack(stack)


@task
def resume_stack(_, stack=None):
    stacks.resume_stack(stack)


@task
def stack(ctx, stack=None):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    ctx.run(f"cat {get_kmt_os().stacks_dir}/{stack}/stack.output")


@task
def ls(_, distro=False, custom=False):
    print(tabulate(vmconfig.get_image_list(distro, custom), headers='firstrow', tablefmt='fancy_grid'))


@task
def init(ctx, lite=False):
    init_kernel_matrix_testing_system(ctx, lite)


@task
def update_resources(ctx):
    kmt_os = get_kmt_os()

    warn("Updating resource dependencies will delete all running stacks.")
    if ask("are you sure you want to continue? (y/n)").lower() != "y":
        raise Exit("[-] Update aborted")

    for stack in glob(f"{kmt_os.stacks_dir}/*"):
        destroy_stack(ctx, stack=os.path.basename(stack))

    update_rootfs(ctx, kmt_os.rootfs_dir)


@task
def build_compiler(ctx):
    build_cc(ctx)


@task
def start_compiler(ctx):
    start_cc(ctx)


class LibvirtDomain:
    def __init__(self, arch, version, name="", ip=""):
        self.arch = arch
        self.version = version
        self.name = name
        self.ip = ip
        self.runner = None
        self.is_vm = True


@dataclass
class MetalInstance:
    name: str
    arch: str
    ip: str
    version: str = ""  # For compatibility
    is_vm: bool = False


def parse_stack_output_line(line):
    name, ip = line.strip().split(' ')
    if name.endswith("-instance-ip"):
        return MetalInstance(name, name.replace('-instance-ip', ''), ip)
    else:
        return LibvirtDomain(name.split('-')[0], name.split('-')[1], name, ip)


def get_all_instances(stack):
    stack_outputs = f"{get_kmt_os().stacks_dir}/{stack}/stack.output"
    with open(stack_outputs, 'r') as f:
        for line in f:
            yield parse_stack_output_line(line)


def get_domain_name_and_ip(stack, version, arch):
    for instance in get_all_instances(stack):
        if instance.is_vm and instance.arch == arch and instance.version == version:
            return instance.name, instance.ip

    raise Exit(f"No entry for ({version}, {arch}) in stack {stack}")


def build_target_domains(ctx, stack, vms, ssh_key, log_debug):
    vmsets = vmconfig.build_vmsets(vmconfig.build_normalized_vm_def_set(vms), [])
    domains = list()
    for vmset in vmsets:
        for vm in vmset.vms:
            d = LibvirtDomain(vmset.arch, vm.version)
            d.name, d.ip = get_domain_name_and_ip(stack, vm.version, vmset.arch)
            d.runner = CommandRunner(ctx, vmset.arch == "local", d, "", ssh_key, log_debug)
            if vmset.arch != "local":
                d.remote_ssh_key = ssh_key
                d.remote_ip = get_instance_ip(stack, vmset.arch)
            domains.append(d)

    return domains


def get_instance_ip(stack, arch):
    for instance in get_all_instances(stack):
        if not instance.is_vm and instance.arch == arch:
            info(f"[*] Instance {instance.name} has ip {instance.ip}")
            return instance.ip


@task
def sync(ctx, vms, stack=None, ssh_key="", verbose=False):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    domains = build_target_domains(ctx, stack, vms, ssh_key, verbose)

    info("[*] VMs to sync")
    for d in domains:
        info(f"    Syncing VM {d.name} with ip {d.ip}")

    if ask("Do you want to sync? (y/n)").lower() != "y":
        warn("[-] Sync aborted !")
        return

    info("[*] Beginning sync...")

    for d in domains:
        d.runner.sync_source("./", "/datadog-agent")


TOOLS_PATH = '/datadog-agent/internal/tools'
GOTESTSUM = "gotest.tools/gotestsum"


def download_gotestsum(ctx):
    fgotestsum = "./test/kitchen/site-cookbooks/dd-system-probe-check/files/default/gotestsum"
    if os.path.isfile(fgotestsum):
        return

    if not os.path.exists("kmt-deps/tools"):
        ctx.run("mkdir -p kmt-deps/tools")

    docker_exec(
        ctx,
        f"cd {TOOLS_PATH} && go install {GOTESTSUM} && cp /go/bin/gotestsum /datadog-agent/kmt-deps/tools/",
    )

    ctx.run(f"cp kmt-deps/tools/gotestsum {fgotestsum}")


def full_arch(arch):
    if arch == "local":
        return arch_mapping[platform.machine()]
    return arch


@task
def prepare(ctx, vms, stack=None, arch=None, ssh_key="", rebuild_deps=False, packages="", verbose=False):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    if vms == "":
        raise Exit("No vms specified to sync with")

    if not arch:
        arch = platform.machine()

    if not compiler_running(ctx):
        start_compiler(ctx)

    download_gotestsum(ctx)

    domains = build_target_domains(ctx, stack, vms, ssh_key, verbose)

    constrain_pkgs = ""
    if not rebuild_deps or (not os.path.isfile(f"kmt-deps/{stack}/dependencies-{arch}.tar.gz")):
        constrain_pkgs = f"--packages={packages}"

    docker_exec(
        ctx,
        f"git config --global --add safe.directory /datadog-agent && inv -e system-probe.kitchen-prepare --ci {constrain_pkgs}",
        run_dir="/datadog-agent",
    )
    if rebuild_deps or not os.path.isfile(f"kmt-deps/{stack}/dependencies-{arch}.tar.gz"):
        docker_exec(
            ctx,
            f"./test/new-e2e/system-probe/test/setup-microvm-deps.sh {stack} {os.getuid()} {os.getgid()} {platform.machine()}",
            run_dir="/datadog-agent",
        )
        for d in domains:
            d.runner.copy_files(f"kmt-deps/{stack}/dependencies-{full_arch(d.arch)}.tar.gz")
            d.runner.run_cmd(f"/root/fetch_dependencies.sh {platform.machine()}", allow_fail=True, verbose=True)
            d.runner.sync_source(
                "./test/kitchen/site-cookbooks/dd-system-probe-check/files/default/tests/pkg",
                "/opt/system-probe-tests",
            )


def build_run_config(run, packages):
    c = dict()

    if len(packages) == 0:
        return {"*": {"exclude": False}}

    for p in packages:
        if p[:2] == "./":
            p = p[2:]
        if run is not None:
            c[p] = {"run-only": [run]}
        else:
            c[p] = {"exclude": False}

    return c


@task
def test(ctx, vms, stack=None, packages="", run=None, retry=2, rebuild_deps=False, ssh_key="", verbose=False):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    prepare(ctx, stack=stack, vms=vms, ssh_key=ssh_key, rebuild_deps=rebuild_deps, packages=packages)

    domains = build_target_domains(ctx, stack, vms, ssh_key, verbose)
    if run is not None and packages is None:
        raise Exit("Package must be provided when specifying test")
    pkgs = packages.split(",")
    if run is not None and len(pkgs) > 1:
        raise Exit("Only a single package can be specified when running specific tests")

    run_config = build_run_config(run, pkgs)
    with tempfile.NamedTemporaryFile(mode='w') as tmp:
        json.dump(run_config, tmp)
        tmp.flush()

        for d in domains:
            d.runner.copy_files(f"{tmp.name}", "/tmp")
            d.runner.run_cmd(f"bash /micro-vm-init.sh {retry} {tmp.name}", verbose=True)


@task
def build(ctx, vms, stack=None, ssh_key="", rebuild_deps=False, verbose=False):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    if not os.path.exists(f"kmt-deps/{stack}"):
        ctx.run(f"mkdir -p kmt-deps/{stack}")

    domains = build_target_domains(ctx, stack, vms, ssh_key, verbose)
    if rebuild_deps or not os.path.isfile(f"kmt-deps/{stack}/dependencies-{platform.machine()}.tar.gz"):
        docker_exec(
            ctx,
            f"./test/new-e2e/system-probe/test/setup-microvm-deps.sh {stack} {os.getuid()} {os.getgid()} {platform.machine()}",
            run_dir="/datadog-agent",
        )
        for d in domains:
            d.runner.copy_files(f"kmt-deps/{stack}/dependencies-{full_arch(d.arch)}.tar.gz")
            d.runner.run_cmd(f"/root/fetch_dependencies.sh {arch_mapping[platform.machine()]}")

    docker_exec(
        ctx, "cd /datadog-agent && git config --global --add safe.directory /datadog-agent && inv -e system-probe.build"
    )
    docker_exec(ctx, f"tar cf /datadog-agent/kmt-deps/{stack}/shared.tar {EMBEDDED_SHARE_DIR}")
    for d in domains:
        d.runner.sync_source("./bin/system-probe", "/root")
        d.runner.sync_source(f"kmt-deps/{stack}/shared.tar", "/")
        d.runner.run_cmd("tar xf /shared.tar -C /")
        info(f"[+] system-probe built for {d.name}")


@task
def clean(ctx, stack=None, container=False, image=False):
    stack = check_and_get_stack(stack)
    if not stacks.stack_exists(stack):
        raise Exit(f"Stack {stack} does not exist. Please create with 'inv kmt.stack-create --stack=<name>'")

    docker_exec(ctx, "inv -e system-probe.clean", run_dir="/datadog-agent")
    ctx.run("rm -rf ./test/kitchen/site-cookbooks/dd-system-probe-check/files/default/tests/pkg")
    ctx.run(f"rm -rf kmt-deps/{stack}", warn=True)
    ctx.run(f"rm {get_kmt_os().shared_dir}/*.tar.gz", warn=True)

    if container:
        ctx.run("docker rm -f $(docker ps -aqf \"name=kmt-compiler\")")
    if image:
        ctx.run("docker image rm kmt:compile")


@task(
    help={
        "stacks": "Comma separated list of stacks to generate ssh config for. 'all' to generate for all stacks.",
        "ddvm_rsa": "Path to the ddvm_rsa file to use for connecting to the VMs. Defaults to the path in the ami-builder repo",
    }
)
def ssh_config(_, stacks=None, ddvm_rsa="~/dd/ami-builder/scripts/kernel-version-testing/files/ddvm_rsa"):
    """
    Print the SSH config for the given stacks.

    Recommended usage: inv kmt.ssh-config --stacks=all > ~/.ssh/config-kmt.
    Then add the following to your ~/.ssh/config:
            Include ~/.ssh/config-kmt

    This makes it easy to use the SSH config for all stacks whenever you change anything,
    without worrying about overriding existing configs.
    """
    stacks_dir = Path(get_kmt_os().stacks_dir)
    stacks_to_print = None

    if stacks is not None and stacks != 'all':
        stacks_to_print = set(stacks.split(','))

    for stack in stacks_dir.iterdir():
        if not stack.is_dir():
            continue

        output = stack / "stack.output"
        if not output.exists():
            continue  # Invalid/removed stack, ignore it

        stack_name = stack.name.replace('-ddvm', '')
        if (
            stacks_to_print is not None
            and 'all' not in stacks_to_print
            and stack_name not in stacks_to_print
            and stack.name not in stacks_to_print
        ):
            continue

        for instance in get_all_instances(stack.name):
            if instance.is_vm:
                print(f"Host kmt-{stack_name}-{instance.arch}-{instance.version}")
                print(f"    HostName {instance.ip}")
                print(f"    ProxyJump kmt-{stack_name}-{instance.arch}")
                print(f"    IdentityFile {ddvm_rsa}")
                print("    User root")
                # Disable host key checking, the IPs of the QEMU machines are reused and we don't want constant
                # warnings about changed host keys. We need the combination of both options, if we just set
                # StrictHostKeyChecking to no, it will still check the known hosts file and disable some options
                # and print out scary warnings if the key doesn't match.
                print("    UserKnownHostsFile /dev/null")
                print("    StrictHostKeyChecking accept-new")
                print("")
            else:
                print(f"Host kmt-{stack_name}-{instance.arch}")
                print(f"    HostName {instance.ip}")
                print("    User ubuntu")
                print("")
