import { FaLinkedin, FaGithub } from 'react-icons/fa'; // Import LinkedIn and GitHub icons
import { MdEmail } from 'react-icons/md';

const ContactPage = () => {
    return (
      <main className="flex-grow container mx-auto px-4 sm:px-6 lg:px-8">
          <h1 className="text-xl sm:text-2xl font-bold text-white p-5">Hey There</h1>
          <h1 className="text-lg sm:text-xl font-bold text-white p-5">Feel free to contact me!</h1>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 p-5">
              <a href="https://www.linkedin.com/in/gnapaC/" 
                className="text-white hover:text-slate-300 text-xl sm:text-2xl">
                  <FaLinkedin className="inline-block mr-2" />LinkedIn
              </a>

              <a href="https://github.com/broCapang" 
                className="text-white hover:text-slate-300 text-xl sm:text-2xl">
                  <FaGithub className="inline-block mr-2" />GitHub
              </a>
              <a href="mailto:ihaziq18.ih@gmail.com" 
                className="text-white hover:text-slate-300 text-xl sm:text-2xl">
                  <MdEmail className="inline-block mr-2" />Email
              </a>
          </div>
      </main>

    );
}
export default ContactPage;