#!/bin/bash
####################################
# Build and test the RVM library
####################################

export DIR=rvm_segments
export OUT=test_output

# ==================================
# === Useful functions

function init {
    if [ ! -e $OUT ]
    then
        mkdir $OUT
    else 
        rm -f $OUT/*
    fi
}

function note {
    echo
    echo "========================"
    echo "== $1"
    echo "========================"
}

function fail {
    echo
    echo "========================"
    echo "===> $1"
    echo "========================"
    echo "  RVM Tests  -  FAILED  "
    echo "========================"
    exit 1
}

function pass {
    echo
    echo "========================"
    echo "  RVM Tests SUCCESSFUL  "
    echo "========================"
    exit 0
}

function check {
    local RC=$1
    local WHAT=$2
    if [ $RC -ne 0 ]
    then
        fail "RetCode $RC from $WHAT"
    fi    
}

function do_it {
    note "$*"
    $@ 2>&1 > "$OUT/$*.out"
    check $? $*
}


# ==================================
# === Useful Assertions

function assert_not_file {
    local FILE=$DIR/$1
    if [ -f $FILE ]
    then
        fail "File: $FILE exists when it should not"
    fi
}

function assert_file {
    local FILE=$DIR/$1
    if [ ! -f $FILE ]
    then
        fail "File: $FILE does not exist"
    fi
}

function assert_dir {
    local DIR=$1
    if [ ! -d $DIR ]
    then
        fail "Dir: $DIR does not exist"
    fi
}

function assert_filesize {
    local FILE=$DIR/$1
    local EXP_SIZE=$2
    local ACT_SIZE=$(ls -l $FILE | cut -d' ' -f5)
    if [ $EXP_SIZE -ne $ACT_SIZE ]
    then 
        fail "File: $FILE wrong size: $ACT_SIZE (exp:$EXP_SIZE)"
    fi
}


# ==================================
# === Test run

init

echo "========================================================================="
echo " Test 1 (tests for consistency across processes)"
echo "========================================================================="

do_it make rvm_test1

do_it ./rvm_test1

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 1 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 2 (tests that aborting a transaction undoes the changes)"
echo "========================================================================="

do_it make rvm_test2

do_it ./rvm_test2

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 2 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 3 (tests for consistency across processes w/ multiple segments)"
echo "========================================================================="

do_it make rvm_test3

do_it ./rvm_test3

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 3 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 4 (tests that aborting undoes changes in multiple segments)"
echo "========================================================================="

do_it make rvm_test4

do_it ./rvm_test4

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 4 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 5 (tests a commit, abort, commit sequence)"
echo "========================================================================="

do_it make rvm_test5

do_it ./rvm_test5

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 5 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 6 (tests that unlogged modification is lost on process termination)"
echo "========================================================================="

do_it make rvm_test6

do_it ./rvm_test6

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 6 Complete"
echo "========================================================================="

echo "========================================================================="
echo " Test 7 (tests that a segment may only be involved in one transaction)"
echo "========================================================================="

do_it make rvm_test7

do_it ./rvm_test7

rm -r $DIR/*

do_it make clean

echo "========================================================================="
echo " Test 7 Complete"
echo "========================================================================="

### finally:

pass

####################################
