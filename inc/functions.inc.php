<?php

function signupInputEmptyCheck($Firstname, $Lastname, $Username, $email, $pwd, $Confpwd) {
    $result;
    if (empty($Firstname) || empty($Lastname) || empty($Username) || empty($email) || empty($pwd) || empty($Confpwd)) {
        $result = true;
    }
    else {
        $result = false;
    }
    return $result;

}   
function invalidID($Username) {
    $result;
    if (!preg_match("/^[a-zA-Z0-9]*$/", $Username)) {
        $result = true;
    }
    else {
        $result = false;
    }
    return $result;

}
function invalidEmail($email) {
    $result;
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $result = true;
    }
    else {
        $result = false;
    }
    return $result;

}
function invalidPWD($pwd) {
    $result;
    if (!preg_match("#[a-zA-z0-9]+#", $pwd) || strlen($pwd) <= 8 ) {
        $result = true;
    }
    else {
        $result = false;
    }
    return $result;

}
function invalidConfPwd($pwd, $Confpwd) {
    $result;
    if ($pwd !== $Confpwd) {
        $result = true;
    }
    else {
        $result = false;
    }
    return $result;

}

function idTaken($conn, $Username, $email) {
    $sql = "SELECT * FROM users WHERE usersUid = ? OR usersEmail = ?;";
    $stmt = mysqli_stmt_init($conn);
    mysqli_stmt_prepare($stmt, $sql);
    if (!mysqli_stmt_prepare($stmt, $sql)) {
        header("location: ../signin.php?error:201"); // error 201
        exit();
    }

    mysqli_stmt_bind_param($stmt, "ss", $Username, $email);
    mysqli_stmt_execute($stmt);

    $resultData = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($resultData)) {
        return $row;
    }
    else {
        $result = false;
        return $result;
    }

    mysqli_stmt_close($stmt);
   
}
function createUser($conn, $Firstname, $Lastname, $Username, $email, $pwd) {
    $sql = "INSERT INTO users(usersName, usersEmail, usersUid, usersPwd) VALUES (?, ?, ?, ?, ?);";
    $stmt = mysqli_stmt_init($conn);
    if (!mysqli_stmt_prepare($stmt, $sql)) {
        header("location: ../signin.php?error:201"); 
        exit();
    }

    $hashedpwd = password_hash($pwd, PASSWORD_DEFAULT);

    mysqli_stmt_bind_param($stmt, "sssss", $Firstname, $Lastname, $Username, $email, $hashedpwd);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
    header("location: ../signin.php?error=none"); //later put the user page here 
   

    

}