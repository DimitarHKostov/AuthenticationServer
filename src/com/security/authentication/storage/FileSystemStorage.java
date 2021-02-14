package com.security.authentication.storage;

import com.google.gson.Gson;
import com.security.authentication.crypt.PasswordCrypter;
import com.security.authentication.enums.ChangeRequest;
import com.security.authentication.exceptions.crypt.DecryptFailException;
import com.security.authentication.exceptions.crypt.EncryptFailException;
import com.security.authentication.exceptions.storage.RemoveFailException;
import com.security.authentication.exceptions.storage.StorageFailException;
import com.security.authentication.exceptions.storage.UserNotFoundException;
import com.security.authentication.exceptions.update.NoUpdateRequestException;
import com.security.authentication.exceptions.update.UpdateFailException;
import com.security.authentication.user.Admin;
import com.security.authentication.user.RegularUser;
import com.security.authentication.user.User;
import com.security.authentication.user.creator.UserCreator;
import com.security.authentication.user.info.AccountInfo;
import com.security.authentication.user.info.PersonalInfo;
import com.security.authentication.validator.Validator;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class FileSystemStorage implements Storage {
    private final Gson gson = new Gson();
    private final Path usersPath;
    private final PasswordCrypter passwordCrypter;

    public FileSystemStorage(Path usersFile, SecretKey secretKey) {
        usersPath = usersFile;
        passwordCrypter = new PasswordCrypter(secretKey);
    }

    @Override
    public boolean add(User user) throws StorageFailException {
        Validator.validateNotNull(user, "user");

        String cryptedPassword;

        try {
            cryptedPassword = passwordCrypter.encrypt(user.getAccountInfo().getPassword());
        } catch (EncryptFailException e) {
            throw new StorageFailException("failed to encrypt password while adding");
        }

        AccountInfo newAccountInfo = new AccountInfo(user.getAccountInfo().getUsername(), cryptedPassword);
        User toBeAdded;

        if (user.isAuthorized()) {
            toBeAdded = new Admin(newAccountInfo, user.getPersonalInfo());
        } else {
            toBeAdded = new RegularUser(newAccountInfo, user.getPersonalInfo());
        }

        try (var writer = new FileWriter(usersPath.toString(), true)) {
            writer.append(gson.toJson(toBeAdded, User.class)).append(System.lineSeparator()).flush();
        } catch (IOException e) {
            throw new StorageFailException("storage failed");
        }

        return true;
    }

    @Override
    public boolean remove(User user) throws RemoveFailException {
        Validator.validateNotNull(user, "user");

        boolean hasOtherAdmin;

        try {
            hasOtherAdmin = hasOtherAdmin(user);
        } catch (StorageFailException e) {
            throw new RemoveFailException("remove failed");
        }

        if (user.isAuthorized() && !hasOtherAdmin) {
            throw new RemoveFailException("");
        }

        try {
            Path tempPath = Path.of("usersTemp.txt");
            Files.createFile(tempPath);
            BufferedReader reader = new BufferedReader(new FileReader(usersPath.toString()));
            BufferedWriter writer = new BufferedWriter(new FileWriter(tempPath.toString()));

            User toBeRemoved = extract(user.getAccountInfo().getUsername());
            String currentLine;

            while ((currentLine = reader.readLine()) != null) {
                User decrypted;

                try {
                    decrypted = extractUserWithDecryptedPassword(gson.fromJson(currentLine, User.class));
                } catch (DecryptFailException e) {
                    throw new RemoveFailException("removing failed");
                }

                if (decrypted.equals(toBeRemoved)) {
                    continue;
                }

                writer.write(currentLine + System.lineSeparator());
            }
            writer.close();
            reader.close();

            String userFileName = usersPath.toString();
            Files.delete(usersPath);
            Files.move(tempPath, Path.of(userFileName));
        } catch (IOException e) {
            throw new RemoveFailException("failed to remove user1");
        } catch (UserNotFoundException e) {
            throw new RemoveFailException("failed to remove user2");
        } catch (StorageFailException e) {
            throw new RemoveFailException("failed to remove user3");
        }

        return true;
    }

    private boolean hasOtherAdmin(User user) throws StorageFailException {
        String line;

        try (var r = new BufferedReader(new FileReader(usersPath.toString()))) {
            while ((line = r.readLine()) != null) {
                User currentUser = gson.fromJson(line, User.class);

                if (currentUser.isAuthorized()
                        && !currentUser.getAccountInfo().getUsername().equals(user.getAccountInfo().getUsername())) {
                    return true;
                }
            }
        } catch (IOException e) {
            throw new StorageFailException("storage failed");
        }

        return false;
    }

    @Override
    public boolean update(User user, Map<ChangeRequest, String> requests)
            throws UpdateFailException,
            NoUpdateRequestException {
        Validator.validateNotNull(user, "user");
        Validator.validateNotNull(requests, "requests");

        try {
            hasStoredInfo(user);
        } catch (StorageFailException e) {
            throw new UpdateFailException("update failed");
        }

        if (requests.size() == 0) {
            throw new NoUpdateRequestException("no updates requested");
        }

        try {
            remove(user);
        } catch (RemoveFailException e) {
            throw new UpdateFailException("update failed");
        }

        try {
            add(changeUserData(user, requests));
        } catch (StorageFailException e) {
            throw new UpdateFailException("storage failed");
        }

        return true;
    }

    private User changeUserData(User user, Map<ChangeRequest, String> requests) {
        String newPassword = null;
        String newFirstName = null;
        String newLastName = null;
        String newEmail = null;
        String newUsername = null;

        for (Map.Entry<ChangeRequest, String> entry : requests.entrySet()) {
            switch (entry.getKey()) {
                case NEW_EMAIL -> newEmail = entry.getValue();
                case NEW_PASSWORD -> newPassword = entry.getValue();
                case NEW_FIRST_NAME -> newFirstName = entry.getValue();
                case NEW_USERNAME -> newUsername = entry.getValue();
                case NEW_LAST_NAME -> newLastName = entry.getValue();
                default -> throw new RuntimeException("unreachable");
            }
        }

        String finalUsername = newUsername != null ? newUsername : user.getAccountInfo().getUsername();
        String finalPassword = newPassword != null ? newPassword : user.getAccountInfo().getPassword();
        String finalFirstName = newFirstName != null ? newFirstName : user.getPersonalInfo().getFirstName();
        String finalLastName = newLastName != null ? newLastName : user.getPersonalInfo().getLastName();
        String finalEmail = newEmail != null ? newEmail : user.getPersonalInfo().getEmail();

        AccountInfo accountInfo = new AccountInfo(finalUsername, finalPassword);
        PersonalInfo personalInfo = new PersonalInfo(finalFirstName, finalLastName, finalEmail);

        return UserCreator.create(accountInfo, personalInfo);
    }

    @Override
    public boolean hasStoredInfo(User user) throws StorageFailException {
        Validator.validateNotNull(user, "user");

        String line;

        try (var r = new BufferedReader(new FileReader(usersPath.toString()))) {
            while ((line = r.readLine()) != null) {
                User currentUser = gson.fromJson(line, User.class);
                if (user.getAccountInfo().getUsername().equals(currentUser.getAccountInfo().getUsername())) {
                    return true;
                }
            }
        } catch (IOException e) {
            throw new StorageFailException("storage failed");
        }

        return false;
    }

    @Override
    public User extract(String username) throws UserNotFoundException, StorageFailException {
        Validator.validateNotNull(username, "username");

        String line;

        try (var r = new BufferedReader(new FileReader(usersPath.toString()))) {
            while ((line = r.readLine()) != null) {
                User currentUser = gson.fromJson(line, User.class);

                User decrypted;
                try {
                    decrypted = extractUserWithDecryptedPassword(currentUser);
                } catch (DecryptFailException e) {
                    throw new StorageFailException("storage failed");
                }

                if (username.equals(decrypted.getAccountInfo().getUsername())) {
                    return decrypted;
                }
            }
        } catch (IOException e) {
            throw new StorageFailException("storage failed");
        }

        throw new UserNotFoundException("user not found");
    }

    @Override
    public boolean isEmpty() {
        try (var r = new BufferedReader(new FileReader(usersPath.toString()))) {
            return r.readLine() == null;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private User extractUserWithDecryptedPassword(User user) throws DecryptFailException {
        String decryptedPassword = passwordCrypter.decrypt(user.getAccountInfo().getPassword());
        AccountInfo newAccountInfo = new AccountInfo(user.getAccountInfo().getUsername(), decryptedPassword);

        if (user.isAuthorized()) {
            return new Admin(newAccountInfo, user.getPersonalInfo());
        }

        return new RegularUser(newAccountInfo, user.getPersonalInfo());
    }
}
