import { Entity, PrimaryGeneratedColumn, ManyToOne, Column } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Project } from '../../project/entities/project.entity';

@Entity('rendering_logs')
export class RenderingLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.id, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Project, (project) => project.id, { onDelete: 'CASCADE' })
  project: Project;

  @Column({ type: 'enum', enum: ['Pending', 'Completed', 'Failed'], default: 'Pending' })
  renderStatus: string;

  @Column({ type: 'timestamp', nullable: true })
  renderedAt: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
