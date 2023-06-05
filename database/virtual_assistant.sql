-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Apr 07, 2022 at 12:38 PM
-- Server version: 5.0.51
-- PHP Version: 5.2.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `virtual_assistant`
--

-- --------------------------------------------------------

--
-- Table structure for table `va_admin`
--

CREATE TABLE `va_admin` (
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_admin`
--

INSERT INTO `va_admin` (`username`, `password`) VALUES
('admin', 'admin'),
('kgc', '1234');

-- --------------------------------------------------------

--
-- Table structure for table `va_register`
--

CREATE TABLE `va_register` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `city` varchar(20) NOT NULL,
  `public_key` varchar(20) NOT NULL,
  `private_key` varchar(20) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `rdate` varchar(20) NOT NULL,
  `status` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_register`
--

INSERT INTO `va_register` (`id`, `name`, `mobile`, `email`, `city`, `public_key`, `private_key`, `uname`, `pass`, `rdate`, `status`) VALUES
(1, 'Siva', 9078933456, 'siva@gmail.com', 'Chennai', '1955b38f', '13116a57', 'siva', '12345', '09-02-2022', 0);

-- --------------------------------------------------------

--
-- Table structure for table `va_reg_kgc`
--

CREATE TABLE `va_reg_kgc` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_reg_kgc`
--

INSERT INTO `va_reg_kgc` (`id`, `name`, `mobile`, `email`, `uname`, `pass`) VALUES
(1, 'Siva', 9078933456, 'siva@gmail.com', 'siva', '12345');

-- --------------------------------------------------------

--
-- Table structure for table `va_share`
--

CREATE TABLE `va_share` (
  `id` int(11) NOT NULL,
  `fid` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `rdate` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_share`
--

INSERT INTO `va_share` (`id`, `fid`, `uname`, `rdate`) VALUES
(1, 1, 'ram', '07-04-2022');

-- --------------------------------------------------------

--
-- Table structure for table `va_user`
--

CREATE TABLE `va_user` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `owner` varchar(20) NOT NULL,
  `gender` varchar(10) NOT NULL,
  `dob` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `location` varchar(50) NOT NULL,
  `desig` varchar(30) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `pass` varchar(20) NOT NULL,
  `public_key` varchar(20) NOT NULL,
  `private_key` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_user`
--

INSERT INTO `va_user` (`id`, `name`, `owner`, `gender`, `dob`, `mobile`, `email`, `location`, `desig`, `uname`, `pass`, `public_key`, `private_key`) VALUES
(1, 'Ram', 'siva', 'Male', '1998-04-02', 9054621096, 'ram@gmail.com', 'Chennai', 'Software', 'ram', '1234', '', '');

-- --------------------------------------------------------

--
-- Table structure for table `va_user_files`
--

CREATE TABLE `va_user_files` (
  `id` int(11) NOT NULL,
  `uname` varchar(20) NOT NULL,
  `file_type` varchar(100) NOT NULL,
  `file_content` varchar(100) NOT NULL,
  `upload_file` varchar(100) NOT NULL,
  `rdate` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_user_files`
--

INSERT INTO `va_user_files` (`id`, `uname`, `file_type`, `file_content`, `upload_file`, `rdate`) VALUES
(1, 'siva', 'text/plain', 'my file', 'F1doc.txt', '09-02-2022'),
(2, 'siva', 'text/plain', 'data', 'F2sample.txt', '16-02-2022'),
(3, 'siva', 'text/plain', 'data', 'F3sampledata.txt', '29-03-2022'),
(4, 'siva', 'text/plain', 'data', 'F4sampledata.txt', '29-03-2022');

-- --------------------------------------------------------

--
-- Table structure for table `va_user_kgc`
--

CREATE TABLE `va_user_kgc` (
  `id` int(11) NOT NULL,
  `name` varchar(20) NOT NULL,
  `owner` varchar(20) NOT NULL,
  `mobile` bigint(20) NOT NULL,
  `email` varchar(40) NOT NULL,
  `public_key` varchar(20) NOT NULL,
  `private_key` varchar(20) NOT NULL,
  `uname` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `va_user_kgc`
--

INSERT INTO `va_user_kgc` (`id`, `name`, `owner`, `mobile`, `email`, `public_key`, `private_key`, `uname`) VALUES
(1, 'Ram', 'siva', 9054621096, 'ram@gmail.com', '4641999a', '7679fcae', 'ram');
