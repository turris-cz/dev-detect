import pytest


def test_store(storage):
    """Test simple write"""
    storage.store('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


def test_store_again(storage):
    """Test that only unique values are stored"""
    storage.store('aa:bb:cc:dd:ee:ff')
    storage.store('aa:bb:cc:dd:ee:ff')

    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


@pytest.mark.parametrize(
    'storage, searched',
    [
        (['aa:bb:cc:dd:ee:ff'], 'aa:bb:cc:dd:ee:ff'),
        pytest.param(['aa:bb:cc:dd:ee:ff'], 'a1:b2:c2:d4:e5:f6', marks=pytest.mark.xfail),
        pytest.param(['aa:bb:cc:dd:ee:ff'], 'aaaa', marks=pytest.mark.xfail),
    ],
    indirect=['storage']
)
def test_search(storage, searched):
    res = storage.search(searched)
    assert res is True


@pytest.mark.parametrize(
    'storage', [('aa:bb:cc:dd:ee:ff',)],
    indirect=True
)
def test_remove(storage):
    storage.remove('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == []


@pytest.mark.parametrize(
    'storage',
    [
        ('aa:bb:cc:dd:ee:ff', 'a1:b2:c3:d4:e5:f6',)
    ],
    indirect=True
)
def test_clear(storage):
    storage.clear()
    macs = storage.get_known()

    assert macs == []
