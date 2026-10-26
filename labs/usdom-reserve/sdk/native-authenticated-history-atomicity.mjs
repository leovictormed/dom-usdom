function need(failures,source,pattern,code) {
  if(!pattern.test(source)) failures.push(code);
}

export function validateNativeAuthenticatedHistoryAtomicity({rpcClient,wallet}) {
  if(typeof rpcClient!=='string' || typeof wallet!=='string') {
    throw new TypeError('authenticated history Rust sources are required');
  }
  const failures=[];
  need(failures,rpcClient,
    /pub struct AuthenticatedHistoryScan \{[\s\S]*?\n    trusted_tip:[\s\S]*?\n    blocks:[\s\S]*?\n    terminal_state_root:/,
    'completed_scan_fields_not_private');
  need(failures,rpcClient,
    /pub fn into_blocks\(self\) -> Vec<CanonicalWalletBlock> \{\s*self\.blocks\s*\}/,
    'completed_scan_not_consumed_as_one_sequence');
  need(failures,rpcClient,
    /loop \{[\s\S]*?scan_authenticated_history_page[\s\S]*?blocks\.extend\(page\.blocks\)[\s\S]*?let Some\(\(next_height, anchor\)\) = page\.continuation else \{[\s\S]*?break;/,
    'pages_not_held_until_terminal_continuation');
  need(failures,rpcClient,
    /if blocks\.len\(\) !=[\s\S]*?blocks\.last\(\)[\s\S]*?Some\(trusted_tip\)[\s\S]*?return Err/,
    'terminal_tip_not_required_before_release');
  need(failures,rpcClient,
    /checked_history_rescan_bytes\(response_bytes, page\.response_bytes\)\?/,
    'cumulative_history_bytes_not_bounded');
  need(failures,wallet,
    /pub fn apply_authenticated_history\([\s\S]*?let original_height = self\.tip_height;[\s\S]*?if let Err\(error\) = self\.apply_block[\s\S]*?while self\.tip_height > original_height[\s\S]*?self\.tip_identifier != original_identifier/,
    'wallet_history_application_not_atomic');
  need(failures,wallet,
    /apply_authenticated_history_and_recover_deposit\([\s\S]*?self\.apply_authenticated_history\(wallet, blocks\)\?[\s\S]*?recover_canonical_deposit[\s\S]*?while self\.tip_height > original_height/,
    'deposit_recovery_not_in_same_rollback_boundary');
  return failures;
}
