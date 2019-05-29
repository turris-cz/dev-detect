def test_get_known(storage):
    """Test that storage return list of mac addresses"""
    macs = storage.get_known()

    assert isinstance(macs, list)


def test_write_new(storage):
    """Test simple write"""
    storage.write_new('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


def test_write_new_multiple(storage):
    """Test write of multiple records"""
    storage.write_new('aa:bb:cc:dd:ee:ff')
    storage.write_new('a1:b2:c3:d4:e5:f6')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff', 'a1:b2:c3:d4:e5:f6']


def test_search(storage):
    storage.write_new('aa:bb:cc:dd:ee:ff')
    res = storage.search('aa:bb:cc:dd:ee:ff')

    assert res is True


def test_search_nonexisting(storage):
    storage.write_new('aa:bb:cc:dd:ee:ff')
    res = storage.search('a1:b2:c2:d4:e5:f6')

    assert res is False


def test_search_nonsense(storage):
    storage.write_new('aa:bb:cc:dd:ee:ff')
    res = storage.search('aaaa')

    assert res is False


def test_remove(storage):
    storage.write_new('aa:bb:cc:dd:ee:ff')
    storage.remove('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == []


def test_clear(storage):
    storage.write_new('aa:bb:cc:dd:ee:ff')
    storage.write_new('a1:b2:c3:d4:e5:f6')

    storage.clear()
    macs = storage.get_known()

    assert macs == []
