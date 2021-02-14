package com.security.authentication.storage;

import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.exceptions.storage.RemoveFailException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.exceptions.update.UpdateFailException;
import com.security.authentication.user.User;

import java.util.Map;

public interface Storage {
    boolean add(User user) throws StorageFailException;

    boolean remove(User user) throws RemoveFailException;

    boolean update(User user, Map<ChangeRequest, String> requestSet)
            throws UpdateFailException,
            NoUpdateRequestException;

    boolean hasStoredInfo(User user) throws StorageFailException;

    User extract(String username) throws UserNotFoundException, StorageFailException;

    boolean isEmpty();
}
