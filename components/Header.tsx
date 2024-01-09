"use client";
import React, { useState } from 'react';
import { VscAccount } from 'react-icons/vsc'; // Example icon import

const Header: React.FC = () => {
    const [isNavVisible, setIsNavVisible] = useState<boolean>(false);

    const toggleNav = () => {
        setIsNavVisible(!isNavVisible);
    };

    return (
        <header className="bg-slate-800 text-white">
            <nav className="bg-white border-gray-200 dark:bg-gray-900 rounded-md mt-6 my-6">
                <div className="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
                    <a href="/" className="flex items-center space-x-3 rtl:space-x-reverse">
                        
                        <VscAccount alt="Human Logo" /> 
                        <span className="self-center text-2xl font-semibold whitespace-nowrap hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-blue-700 md:p-0 dark:text-white md:dark:hover:text-blue-500 dark:hover:bg-gray-700 dark:hover:text-white md:dark:hover:bg-transparent">Irfan Haziq</span>
                    </a>
                    <button
                        onClick={toggleNav}
                        type="button"
                        className="inline-flex items-center p-2 w-10 h-10 justify-center text-sm text-gray-500 rounded-lg md:hidden hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-200 dark:text-gray-400 dark:hover:bg-gray-700 dark:focus:ring-gray-600"
                        aria-controls="navbar-default"
                        aria-expanded={isNavVisible}
                    >
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16"></path>
                        </svg>
                    </button>
                    <div className={`${isNavVisible ? 'block' : 'hidden'} w-full md:block md:w-auto`} id="navbar-default">
                        <ul className="flex flex-col md:flex-row md:space-x-8 p-4 mt-4 md:mt-0 text-center">
                            <li><a href="/" className="py-2 px-3 text-gray-900 rounded hover:bg-gray-600 dark:text-white">Home</a></li>
                            <li><a href="/about" className="py-2 px-3 text-gray-900 rounded hover:bg-gray-600 dark:text-white">About</a></li>
                            <li><a href="/writeups" className="py-2 px-3 text-gray-900 rounded hover:bg-gray-600 dark:text-white">Writeups</a></li>
                            <li><a href="/contact" className="py-2 px-3 text-gray-900 rounded hover:bg-gray-600 dark:text-white">Contact</a></li>
                        </ul>
                    </div>
                </div>
            </nav>
        </header>
    );
};

export default Header;
