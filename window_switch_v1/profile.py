"""Explicit v2 profile selects a leaf root; bytes alone establish its targets."""
import json
from window_profile_v1 import profile as legacy
from window_profile_v1.profile import read_input, read_profile, require

CONTRACT = 'win32-d3d11-tile-switch-v1'
FIELDS = legacy.FIELDS | {'switch_leaf_rva'}
LIMITS = dict(legacy.LIMITS, isa='window subset plus one independently proven scalar rel32 leaf',
              switch='one declared leaf root, 2..32 signed rel32 entries; no configured target authorization')


def validate(data, profile):
    require(type(profile) is dict and set(profile) == FIELDS, 'exact window-switch profile fields required')
    require(type(profile['schema']) is int and profile['schema'] == 2, 'window-switch profile schema must be 2')
    require(profile['runtime_contract'] == CONTRACT, 'window-switch runtime contract required')
    old = {k: v for k, v in profile.items() if k in legacy.FIELDS}
    old.update(schema=1, runtime_contract=legacy.CONTRACT)
    _, image, info = legacy.validate(data, old)
    leaf = profile['switch_leaf_rva']
    require(type(leaf) is int and 0 <= leaf < len(image.data) and
            image.permissions[leaf // 4096] == 5, 'switch leaf must be an integer RX image RVA')
    require(leaf not in [image.entry_rva, *profile['callback_rvas']], 'leaf is not a main/callback root')
    return json.loads(json.dumps(profile)), image, info


def analyze(data, profile):
    result = dict(schema=2, profile=CONTRACT, guest_executions=0, limits=LIMITS)
    try:
        normalized, image, info = validate(data, profile)
        result.update(status='ELIGIBLE_FOR_BUILD_NOT_DECODED', input_sha256=image.source_sha256,
                      callback_rvas=normalized['callback_rvas'], switch_leaf_rva=normalized['switch_leaf_rva'],
                      inventory=info, imports=image.imports)
    except ValueError as error:
        result.update(status='UNSUPPORTED', stage='profile-or-loader', error=str(error))
    return result
