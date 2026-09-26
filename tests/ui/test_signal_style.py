from wifit3.ui.signal_bar import dbm_style


def test_dbm_style_uses_one_scale_for_all_radios():
    assert dbm_style(-40) == "bold green"
    assert dbm_style(-50) == "bold green"
    assert dbm_style(-51) == "cyan"
    assert dbm_style(-67) == "cyan"
    assert dbm_style(-68) == "yellow"
    assert dbm_style(-80) == "yellow"
    assert dbm_style(-81) == "red"
    assert dbm_style(-81, dim=True) == "dim red"
