"""Strict project configuration; relative paths are relative to this file."""
import hashlib
import json
import os
from pathlib import Path
import stat

from real_pe_inventory_v1.inventory import read_input
from window_app_v1.noarg import spec

ROOT = Path(__file__).resolve().parents[1]
PE_SHA = '39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8'
PROFILE_SHA = 'c3974063866c3c80c4e1cb9af46748cc8c2f6039ae286bc6c8afb12c1dd74d76'


class WorkflowError(ValueError):
    def __init__(self, code, message, field=None, next_action=None):
        super().__init__(message)
        self.code, self.field, self.next_action = code, field, next_action


def require(ok, code, message, field=None, next_action=None):
    if not ok:
        raise WorkflowError(code, message, field, next_action)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'INVALID_JSON', '重复JSON字段: '+key)
        value[key] = item
    return value


def decode(data):
    return json.loads(data, object_pairs_hook=_pairs,
        parse_constant=lambda v: require(False, 'INVALID_JSON', '不允许非有限JSON数字: '+v))


def canonical(value, base=None):
    require(isinstance(value, (str, Path)) and bool(str(value)) and len(str(value)) <= 4096,
            'INVALID_PATH', '需要非空路径')
    p = Path(value)
    if not p.is_absolute():
        p = (Path(base) if base else Path.cwd())/p
    require(not any(part.is_symlink() for part in (p, *p.parents)), 'SYMLINK_PATH', '路径不能经过符号链接: '+str(p))
    p = Path(os.path.abspath(p))
    require(p == p.resolve(), 'SYMLINK_PATH', '路径不能经过符号链接: '+str(p))
    return p


def read_bounded(path, limit, code='JSON_TOO_LARGE'):
    path=canonical(path)
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode),'NONREGULAR_INPUT','需要普通文件: '+str(path))
        require(before.st_size<=limit,code,'文件超过读取上限: '+str(path))
        with os.fdopen(fd,'rb') as stream:
            fd=None;raw=stream.read(limit+1);after=os.fstat(stream.fileno())
    finally:
        if fd is not None:os.close(fd)
    current=path.stat(follow_symlinks=False)
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
    require(len(raw)<=limit and len(raw)==before.st_size and identity(before)==identity(after)==identity(current),
            'INPUT_CHANGED','读取期间文件变化: '+str(path))
    return raw


def read_json(path, limit=32*1024*1024):
    return decode(read_bounded(path,limit))


def normalize(value, path):
    require(type(value) is dict and set(value) == {'schema','pe','profile','identifier','build'},
            'INVALID_CONFIG', '配置必须包含schema/pe/profile/identifier/build且无额外字段')
    require(type(value['schema']) is int and value['schema'] == 1, 'INVALID_CONFIG', '配置schema必须为1')
    require(type(value['pe']) is str and (value['profile'] is None or type(value['profile']) is str),
            'INVALID_CONFIG', 'pe必须是路径，profile必须是路径或null')
    spec(dict(identifier=value['identifier'], name='PE AOT Portable Window'))
    build = value['build']
    require(type(build) is dict and build.get('mode') in ('providers','offline'), 'INVALID_CONFIG', 'build.mode必须为providers或offline')
    fields = {'mode','cpu_prefix','graphics_prefix'} if build['mode']=='providers' else {'mode','cpu_cache','graphics_cache','jobs'}
    require(set(build)==fields, 'INVALID_CONFIG', '两种build模式字段不能混用或省略', 'build')
    if build['mode']=='offline':
        require(type(build['jobs']) is int and 1 <= build['jobs'] <= 2, 'INVALID_CONFIG', 'jobs只能为1或2', 'build.jobs')
    result = dict(value, pe=str(canonical(value['pe'], path.parent)), build=dict(build))
    if value['profile'] is not None:
        result['profile'] = str(canonical(value['profile'], path.parent))
    for field in fields-{'mode','jobs'}:
        require(type(build[field]) is str, 'INVALID_CONFIG', '依赖路径必须是字符串', 'build.'+field)
        result['build'][field] = str(canonical(build[field], path.parent))
    return result


def load_config(path):
    path = canonical(path); raw = read_bounded(path,65536,'CONFIG_TOO_LARGE')
    return dict(path=str(path), sha256=digest(raw), value=normalize(decode(raw),path))


def select_profile(config, pe_data):
    selected = config['value']['profile']
    if selected is not None:
        return dict(path=selected, selection='explicit_profile')
    require(digest(pe_data)==PE_SHA, 'PROFILE_REQUIRED', '该PE没有已审核的内置配置，不能自动猜测回调或switch根',
            'profile', '提供匹配且已审核的profile；保留静态库存用于后续兼容开发')
    path = ROOT/'examples/window-switch/profile.json'
    require(digest(read_input(path))==PROFILE_SHA, 'BUILTIN_RECIPE_CHANGED', '内置profile原字节身份变化')
    return dict(path=str(path), selection='builtin_exact_pe_sha256', pe_sha256=PE_SHA, profile_sha256=PROFILE_SHA)


def initialize(path, value):
    path=canonical(path)
    require(path.parent.is_dir() and not path.exists(), 'CONFIG_OUTPUT_EXISTS', '配置需要已存在的父目录和新的文件名')
    raw=encode(value)
    require(len(raw)<=65536, 'CONFIG_TOO_LARGE', '配置最大64KiB')
    normalize(decode(raw),path)
    with path.open('xb') as stream:
        stream.write(raw)
    return dict(status='MIGRATION_CONFIG_CREATED_NOT_CHECKED', config=str(path), config_sha256=digest(raw))
