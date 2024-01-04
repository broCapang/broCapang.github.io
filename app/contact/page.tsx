import { FaLinkedin, FaGithub } from 'react-icons/fa'; // Import LinkedIn and GitHub icons
import { MdEmail } from 'react-icons/md';

const ContactPage = () => {
    return (
        <main className="flex-grow container mx-auto">
        <h1 className="text-2xl font-bold text-white p-10">Hey There</h1>
        <h1 className="text-xl font-bold text-white p-10">Feel free to contact me!</h1>
        
        <div className="grid grid-cols-3 gap-4 p-10">
          <a href="https://www.linkedin.com/in/gnapaC/" 
             className="text-white hover:text-slate-300 text-2xl">
            <FaLinkedin className="inline-block mr-2" />LinkedIn
          </a>

          <a href="https://github.com/broCapang" 
             className="text-white hover:text-slate-300 text-2xl">
            <FaGithub className="inline-block mr-2" />GitHub
          </a>
          <a href="mailto:ihaziq18.ih@gmail.com" 
             className="text-white hover:text-slate-300 text-2xl">
            <MdEmail className="inline-block mr-2" />Email
          </a>
        </div>
      </main>
    );
}
export default ContactPage;